// SPDX-License-Identifier: GPL-2.0-only
/*
 * vgic_lpi_stress - Stress test for KVM's ITS emulation
 *
 * Copyright (c) 2024 Google LLC
 */

#include <linux/sizes.h>
#include <pthread.h>
#include <sys/sysinfo.h>

#include "kvm_util.h"
#include "gic.h"
#include "gic_v3.h"
#include "processor.h"
#include "ucall.h"
#include "vgic.h"

#define TEST_MEMSLOT_INDEX	1

#define GIC_LPI_OFFSET	8192

static u32 nr_vcpus = 1;
static u32 nr_devices = 1;
static u32 nr_event_ids = 16;
static size_t nr_iterations = 1000;
static vm_paddr_t gpa_base;

static struct kvm_vm *vm;
static struct kvm_vcpu **vcpus;
static struct vgic_its *its;
static int gic_fd;

static bool request_vcpus_stop;

static void guest_irq_handler(struct ex_regs *regs)
{
	u32 intid = gic_get_and_ack_irq();

	if (intid == IAR_SPURIOUS)
		return;

	GUEST_ASSERT(intid >= GIC_LPI_OFFSET);
	gic_set_eoi(intid);
}

static void guest_code(size_t nr_lpis)
{
	gic_init(GIC_V3, nr_vcpus);

	GUEST_SYNC(0);

	/*
	 * Don't use WFI here to avoid blocking the vCPU thread indefinitely and
	 * never getting the stop singal.
	 */
	while (!READ_ONCE(request_vcpus_stop))
		cpu_relax();

	GUEST_DONE();
}

static void setup_memslot(void)
{
	size_t pages;
	size_t sz;

	/*
	 * For the ITS:
	 *  - A single level device table
	 *  - A single level collection table
	 *  - The command queue
	 *  - An ITT for each device
	 */
	sz = (3 + nr_devices) * SZ_64K;

	/*
	 * For the redistributors:
	 *  - A shared LPI configuration table
	 *  - An LPI pending table for each vCPU
	 */
	sz += (1 + nr_vcpus) * SZ_64K;

	pages = sz / vm->page_size;
	gpa_base = ((vm_compute_max_gfn(vm) + 1) * vm->page_size) - sz;
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, gpa_base,
				    TEST_MEMSLOT_INDEX, pages, 0);
}

#define LPI_PROP_DEFAULT_PRIO	0xa0

static void configure_lpis(vm_paddr_t prop_table)
{
	u8 *tbl = addr_gpa2hva(vm, prop_table);
	size_t i;

	for (i = 0; i < (nr_devices * nr_event_ids); i++) {
		tbl[i] = LPI_PROP_DEFAULT_PRIO |
			 LPI_PROP_GROUP1 |
			 LPI_PROP_ENABLED;
	}
}

static void setup_gic(void)
{
	vm_paddr_t coll_table, device_table, cmdq_base;

	gic_fd = vgic_v3_setup(vm, nr_vcpus, 64);
	__TEST_REQUIRE(gic_fd >= 0, "Failed to create GICv3");

	coll_table = vm_phy_pages_alloc_aligned(vm, SZ_64K / vm->page_size,
						gpa_base, TEST_MEMSLOT_INDEX);
	device_table = vm_phy_pages_alloc_aligned(vm, SZ_64K / vm->page_size,
						  gpa_base, TEST_MEMSLOT_INDEX);
	cmdq_base = vm_phy_pages_alloc_aligned(vm, SZ_64K / vm->page_size,
					       gpa_base, TEST_MEMSLOT_INDEX);

	its = vgic_its_setup(vm, coll_table, SZ_64K,
			     device_table, SZ_64K, cmdq_base, SZ_64K);
}

static void setup_its_mappings(void)
{
	u32 coll_id, device_id, event_id, intid = GIC_LPI_OFFSET;

	for (coll_id = 0; coll_id < nr_vcpus; coll_id++)
		vgic_its_send_mapc_cmd(its, vcpus[coll_id], coll_id, true);

	/* Round-robin the LPIs to all of the vCPUs in the VM */
	coll_id = 0;
	for (device_id = 0; device_id < nr_devices; device_id++) {
		vm_paddr_t itt_base = vm_phy_pages_alloc_aligned(vm, SZ_64K / vm->page_size,
								 gpa_base, TEST_MEMSLOT_INDEX);

		vgic_its_send_mapd_cmd(its, device_id, itt_base, SZ_64K, true);

		for (event_id = 0; event_id < nr_event_ids; event_id++) {
			vgic_its_send_mapti_cmd(its, device_id, event_id, coll_id,
						intid++);

			coll_id = (coll_id + 1) % nr_vcpus;
		}
	}
}

static void setup_rdists_for_lpis(void)
{
	size_t i;

	vm_paddr_t prop_table = vm_phy_pages_alloc_aligned(vm, SZ_64K / vm->page_size,
							   gpa_base, TEST_MEMSLOT_INDEX);

	configure_lpis(prop_table);

	for (i = 0; i < nr_vcpus; i++) {
		vm_paddr_t pend_table;

		pend_table = vm_phy_pages_alloc_aligned(vm, SZ_64K / vm->page_size,
							gpa_base, TEST_MEMSLOT_INDEX);

		vgic_rdist_enable_lpis(gic_fd, vcpus[i], prop_table, SZ_64K, pend_table);
	}
}

static void invalidate_all_rdists(void)
{
	int i;

	for (i = 0; i < nr_vcpus; i++)
		vgic_its_send_invall_cmd(its, i);
}

static void signal_lpi(u32 device_id, u32 event_id)
{
	vm_paddr_t db_addr = GITS_BASE_GPA + GITS_TRANSLATER;

	struct kvm_msi msi = {
		.address_lo	= db_addr,
		.address_hi	= db_addr >> 32,
		.data		= event_id,
		.devid		= device_id,
		.flags		= KVM_MSI_VALID_DEVID,
	};

	/*
	 * KVM_SIGNAL_MSI returns 1 if the MSI wasn't 'blocked' by the VM,
	 * which for arm64 implies having a valid translation in the ITS.
	 */
	TEST_ASSERT(__vm_ioctl(vm, KVM_SIGNAL_MSI, &msi) == 1,
		    "KVM_SIGNAL_MSI ioctl failed");
}

static pthread_barrier_t test_setup_barrier;
static pthread_barrier_t test_start_barrier;

static void *lpi_worker_thread(void *data)
{
	u32 device_id = (size_t)data;
	u32 event_id;
	size_t i;

	pthread_barrier_wait(&test_start_barrier);

	for (i = 0; i < nr_iterations; i++)
		for (event_id = 0; event_id < nr_event_ids; event_id++)
			signal_lpi(device_id, event_id);

	return NULL;
}

static void *vcpu_worker_thread(void *data)
{
	struct kvm_vcpu *vcpu = data;
	struct ucall uc;

	while (true) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			/*
			 * Tell the main thread to complete its last bit of
			 * setup and wait for the signal to start the test.
			 */
			pthread_barrier_wait(&test_setup_barrier);
			pthread_barrier_wait(&test_start_barrier);
			break;
		case UCALL_DONE:
			return NULL;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		default:
			TEST_FAIL("Unknown ucall: %lu", uc.cmd);
		}
	}

	return NULL;
}

static void report_stats(struct timespec delta)
{
	u64 cache_hits, cache_misses, cache_accesses;
	double nr_lpis;
	double time;

	nr_lpis = nr_devices * nr_event_ids * nr_iterations;

	time = delta.tv_sec;
	time += ((double)delta.tv_nsec) / NSEC_PER_SEC;

	pr_info("Rate: %.2f LPIs/sec\n", nr_lpis / time);

	__vm_get_stat(vm, "vgic_its_trans_cache_hit", &cache_hits, 1);
	__vm_get_stat(vm, "vgic_its_trans_cache_miss", &cache_misses, 1);

	cache_accesses = cache_hits + cache_misses;

	pr_info("Translation Cache\n");
	pr_info("  %lu hits\n", cache_hits);
	pr_info("  %lu misses\n", cache_misses);
	pr_info("  %.2f%% hit rate\n", 100 * (((double)cache_hits) / cache_accesses));
}

static void run_test(void)
{
	pthread_t *lpi_threads = malloc(nr_devices * sizeof(pthread_t));
	pthread_t *vcpu_threads = malloc(nr_vcpus * sizeof(pthread_t));
	struct timespec start, delta;
	size_t i;

	TEST_ASSERT(lpi_threads && vcpu_threads, "Failed to allocate pthread arrays");

	/* Only the vCPU threads need to do setup before starting the VM. */
	pthread_barrier_init(&test_setup_barrier, NULL, nr_vcpus + 1);
	pthread_barrier_init(&test_start_barrier, NULL, nr_devices + nr_vcpus + 1);

	for (i = 0; i < nr_vcpus; i++)
		pthread_create(&vcpu_threads[i], NULL, vcpu_worker_thread, vcpus[i]);

	for (i = 0; i < nr_devices; i++)
		pthread_create(&lpi_threads[i], NULL, lpi_worker_thread, (void *)i);

	pthread_barrier_wait(&test_setup_barrier);

	/*
	 * Setup LPIs for the VM after the guest has initialized the GIC. Yes,
	 * this is weird to be doing in userspace, but creating ITS translations
	 * requires allocating an ITT for every device.
	 */
	setup_rdists_for_lpis();
	setup_its_mappings();
	invalidate_all_rdists();

	clock_gettime(CLOCK_MONOTONIC, &start);
	pthread_barrier_wait(&test_start_barrier);

	for (i = 0; i < nr_devices; i++)
		pthread_join(lpi_threads[i], NULL);

	delta = timespec_elapsed(start);
	write_guest_global(vm, request_vcpus_stop, true);

	for (i = 0; i < nr_vcpus; i++)
		pthread_join(vcpu_threads[i], NULL);

	report_stats(delta);
}

static void setup_vm(void)
{
	int i;

	vcpus = malloc(nr_vcpus * sizeof(struct kvm_vcpu));
	TEST_ASSERT(vcpus, "Failed to allocate vCPU array");

	vm = vm_create_with_vcpus(nr_vcpus, guest_code, vcpus);

	vm_init_descriptor_tables(vm);
	for (i = 0; i < nr_vcpus; i++)
		vcpu_init_descriptor_tables(vcpus[i]);

	vm_install_exception_handler(vm, VECTOR_IRQ_CURRENT, guest_irq_handler);

	setup_memslot();

	setup_gic();

	/* gic_init() demands the number of vCPUs in the VM */
	sync_global_to_guest(vm, nr_vcpus);
}

static void destroy_vm(void)
{
	vgic_its_destroy(its);
	close(gic_fd);
	kvm_vm_free(vm);
	free(vcpus);
}

static void pr_usage(const char *name)
{
	pr_info("%s [-v NR_VCPUS] [-d NR_DEVICES] [-e NR_EVENTS] [-i ITERS] -h\n", name);
	pr_info("  -v:\tnumber of vCPUs (default: %u)\n", nr_vcpus);
	pr_info("  -d:\tnumber of devices (default: %u)\n", nr_devices);
	pr_info("  -e:\tnumber of event IDs per device (default: %u)\n", nr_event_ids);
	pr_info("  -i:\tnumber of iterations (default: %lu)\n", nr_iterations);
}

int main(int argc, char **argv)
{
	u32 nr_threads;
	int c;

	while ((c = getopt(argc, argv, "hv:d:e:i:")) != -1) {
		switch (c) {
		case 'v':
			nr_vcpus = atoi(optarg);
			break;
		case 'd':
			nr_devices = atoi(optarg);
			break;
		case 'e':
			nr_event_ids = atoi(optarg);
			break;
		case 'i':
			nr_iterations = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			pr_usage(argv[0]);
			return 1;
		}
	}

	nr_threads = nr_vcpus + nr_devices;
	if (nr_threads > get_nprocs())
		pr_info("WARNING: running %u threads on %d CPUs; performance is degraded.\n",
			 nr_threads, get_nprocs());

	setup_vm();

	run_test();

	destroy_vm();

	return 0;
}
