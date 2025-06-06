// SPDX-License-Identifier: GPL-2.0-only
/*
 * STMicroelectronics st_lsm6dsx sensor driver
 *
 * The ST LSM6DSx IMU MEMS series consists of 3D digital accelerometer
 * and 3D digital gyroscope system-in-package with a digital I2C/SPI serial
 * interface standard output.
 * LSM6DSx IMU MEMS series has a dynamic user-selectable full-scale
 * acceleration range of +-2/+-4/+-8/+-16 g and an angular rate range of
 * +-125/+-245/+-500/+-1000/+-2000 dps
 * LSM6DSx series has an integrated First-In-First-Out (FIFO) buffer
 * allowing dynamic batching of sensor data.
 * LSM9DSx series is similar but includes an additional magnetometer, handled
 * by a different driver.
 *
 * Supported sensors:
 *
 * - LSM6DS3
 *   - Accelerometer/Gyroscope supported ODR [Hz]: 12.5, 26, 52, 104, 208, 416
 *   - Accelerometer supported full-scale [g]: +-2/+-4/+-8/+-16
 *   - Gyroscope supported full-scale [dps]: +-125/+-245/+-500/+-1000/+-2000
 *   - FIFO size: 8KB
 *
 * - ISM330DLC
 * - LSM6DS3H
 * - LSM6DS3TR-C
 * - LSM6DSL
 * - LSM6DSM
 *   - Accelerometer/Gyroscope supported ODR [Hz]: 12.5, 26, 52, 104, 208, 416
 *   - Accelerometer supported full-scale [g]: +-2/+-4/+-8/+-16
 *   - Gyroscope supported full-scale [dps]: +-125/+-245/+-500/+-1000/+-2000
 *   - FIFO size: 4KB
 *
 * - ASM330LHH
 * - ASM330LHHX
 * - ASM330LHHXG1
 * - ISM330DHCX
 * - ISM330IS
 * - LSM6DSO
 * - LSM6DSO16IS
 * - LSM6DSOP
 * - LSM6DSOX
 * - LSM6DSR
 * - LSM6DST
 * - LSM6DSTX
 *   - Accelerometer/Gyroscope supported ODR [Hz]: 12.5, 26, 52, 104, 208, 416,
 *     833
 *   - Accelerometer supported full-scale [g]: +-2/+-4/+-8/+-16
 *   - Gyroscope supported full-scale [dps]: +-125/+-245/+-500/+-1000/+-2000
 *   - FIFO size: 3KB
 *
 * - LSM6DSV
 * - LSM6DSV16X
 *   - Accelerometer/Gyroscope supported ODR [Hz]: 7.5, 15, 30, 60, 120, 240,
 *     480, 960
 *   - Accelerometer supported full-scale [g]: +-2/+-4/+-8/+-16
 *   - Gyroscope supported full-scale [dps]: +-125/+-250/+-500/+-1000/+-2000
 *   - FIFO size: 3KB
 *
 * - LSM6DS0
 * - LSM9DS1
 *   - Accelerometer supported ODR [Hz]: 10, 50, 119, 238, 476, 952
 *   - Accelerometer supported full-scale [g]: +-2/+-4/+-8/+-16
 *   - Gyroscope supported ODR [Hz]: 15, 60, 119, 238, 476, 952
 *   - Gyroscope supported full-scale [dps]: +-245/+-500/+-2000
 *   - FIFO size: 32
 *
 * Copyright 2016 STMicroelectronics Inc.
 *
 * Lorenzo Bianconi <lorenzo.bianconi@st.com>
 * Denis Ciocca <denis.ciocca@st.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/iio/events.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/triggered_buffer.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/minmax.h>
#include <linux/pm.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/bitfield.h>

#include <linux/platform_data/st_sensors_pdata.h>

#include "st_lsm6dsx.h"

#define ST_LSM6DSX_REG_WHOAMI_ADDR		0x0f

#define ST_LSM6DSX_TS_SENSITIVITY		25000UL /* 25us */

static const struct iio_chan_spec st_lsm6dsx_acc_channels[] = {
	ST_LSM6DSX_CHANNEL_ACC(IIO_ACCEL, 0x28, IIO_MOD_X, 0),
	ST_LSM6DSX_CHANNEL_ACC(IIO_ACCEL, 0x2a, IIO_MOD_Y, 1),
	ST_LSM6DSX_CHANNEL_ACC(IIO_ACCEL, 0x2c, IIO_MOD_Z, 2),
	IIO_CHAN_SOFT_TIMESTAMP(3),
};

static const struct iio_chan_spec st_lsm6dsx_gyro_channels[] = {
	ST_LSM6DSX_CHANNEL(IIO_ANGL_VEL, 0x22, IIO_MOD_X, 0),
	ST_LSM6DSX_CHANNEL(IIO_ANGL_VEL, 0x24, IIO_MOD_Y, 1),
	ST_LSM6DSX_CHANNEL(IIO_ANGL_VEL, 0x26, IIO_MOD_Z, 2),
	IIO_CHAN_SOFT_TIMESTAMP(3),
};

static const struct iio_chan_spec st_lsm6ds0_gyro_channels[] = {
	ST_LSM6DSX_CHANNEL(IIO_ANGL_VEL, 0x18, IIO_MOD_X, 0),
	ST_LSM6DSX_CHANNEL(IIO_ANGL_VEL, 0x1a, IIO_MOD_Y, 1),
	ST_LSM6DSX_CHANNEL(IIO_ANGL_VEL, 0x1c, IIO_MOD_Z, 2),
	IIO_CHAN_SOFT_TIMESTAMP(3),
};

static const struct st_lsm6dsx_settings st_lsm6dsx_sensor_settings[] = {
	{
		.reset = {
			.addr = 0x22,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x22,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x22,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM9DS1_ID,
				.name = ST_LSM9DS1_DEV_NAME,
				.wai = 0x68,
			}, {
				.hw_id = ST_LSM6DS0_ID,
				.name = ST_LSM6DS0_DEV_NAME,
				.wai = 0x68,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6ds0_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6ds0_gyro_channels),
			},
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x20,
					.mask = GENMASK(7, 5),
				},
				.odr_avl[0] = {  10000, 0x01 },
				.odr_avl[1] = {  50000, 0x02 },
				.odr_avl[2] = { 119000, 0x03 },
				.odr_avl[3] = { 238000, 0x04 },
				.odr_avl[4] = { 476000, 0x05 },
				.odr_avl[5] = { 952000, 0x06 },
				.odr_len = 6,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 5),
				},
				.odr_avl[0] = {  14900, 0x01 },
				.odr_avl[1] = {  59500, 0x02 },
				.odr_avl[2] = { 119000, 0x03 },
				.odr_avl[3] = { 238000, 0x04 },
				.odr_avl[4] = { 476000, 0x05 },
				.odr_avl[5] = { 952000, 0x06 },
				.odr_len = 6,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x20,
					.mask = GENMASK(4, 3),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(732000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(4, 3),
				},

				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 3,
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0c,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.hla = {
				.addr = 0x22,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x22,
				.mask = BIT(4),
			},
		},
		.fifo_ops = {
			.max_size = 32,
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM6DS3_ID,
				.name = ST_LSM6DS3_DEV_NAME,
				.wai = 0x69,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_len = 6,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_len = 6,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x2 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 4,
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0e,
				.mask = BIT(3),
			},
			.lir = {
				.addr = 0x58,
				.mask = BIT(0),
			},
			.irq1_func = {
				.addr = 0x5e,
				.mask = BIT(5),
			},
			.irq2_func = {
				.addr = 0x5f,
				.mask = BIT(5),
			},
			.hla = {
				.addr = 0x12,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x12,
				.mask = BIT(4),
			},
		},
		.decimator = {
			[ST_LSM6DSX_ID_ACC] = {
				.addr = 0x08,
				.mask = GENMASK(2, 0),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.addr = 0x08,
				.mask = GENMASK(5, 3),
			},
		},
		.fifo_ops = {
			.update_fifo = st_lsm6dsx_update_fifo,
			.read_fifo = st_lsm6dsx_read_fifo,
			.fifo_th = {
				.addr = 0x06,
				.mask = GENMASK(11, 0),
			},
			.fifo_diff = {
				.addr = 0x3a,
				.mask = GENMASK(11, 0),
			},
			.max_size = 1365,
			.th_wl = 3, /* 1LSB = 2B */
		},
		.ts_settings = {
			.timer_en = {
				.addr = 0x58,
				.mask = BIT(7),
			},
			.hr_timer = {
				.addr = 0x5c,
				.mask = BIT(4),
			},
			.fifo_en = {
				.addr = 0x07,
				.mask = BIT(7),
			},
			.decimator = {
				.addr = 0x09,
				.mask = GENMASK(5, 3),
			},
		},
		.event_settings = {
			.wakeup_reg = {
				.addr = 0x5B,
				.mask = GENMASK(5, 0),
			},
			.wakeup_src_reg = 0x1b,
			.wakeup_src_status_mask = BIT(3),
			.wakeup_src_z_mask = BIT(0),
			.wakeup_src_y_mask = BIT(1),
			.wakeup_src_x_mask = BIT(2),
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM6DS3H_ID,
				.name = ST_LSM6DS3H_DEV_NAME,
				.wai = 0x69,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_len = 6,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_len = 6,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x2 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 4,
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0e,
				.mask = BIT(3),
			},
			.lir = {
				.addr = 0x58,
				.mask = BIT(0),
			},
			.irq1_func = {
				.addr = 0x5e,
				.mask = BIT(5),
			},
			.irq2_func = {
				.addr = 0x5f,
				.mask = BIT(5),
			},
			.hla = {
				.addr = 0x12,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x12,
				.mask = BIT(4),
			},
		},
		.decimator = {
			[ST_LSM6DSX_ID_ACC] = {
				.addr = 0x08,
				.mask = GENMASK(2, 0),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.addr = 0x08,
				.mask = GENMASK(5, 3),
			},
		},
		.fifo_ops = {
			.update_fifo = st_lsm6dsx_update_fifo,
			.read_fifo = st_lsm6dsx_read_fifo,
			.fifo_th = {
				.addr = 0x06,
				.mask = GENMASK(11, 0),
			},
			.fifo_diff = {
				.addr = 0x3a,
				.mask = GENMASK(11, 0),
			},
			.max_size = 682,
			.th_wl = 3, /* 1LSB = 2B */
		},
		.ts_settings = {
			.timer_en = {
				.addr = 0x58,
				.mask = BIT(7),
			},
			.hr_timer = {
				.addr = 0x5c,
				.mask = BIT(4),
			},
			.fifo_en = {
				.addr = 0x07,
				.mask = BIT(7),
			},
			.decimator = {
				.addr = 0x09,
				.mask = GENMASK(5, 3),
			},
		},
		.event_settings = {
			.wakeup_reg = {
				.addr = 0x5B,
				.mask = GENMASK(5, 0),
			},
			.wakeup_src_reg = 0x1b,
			.wakeup_src_status_mask = BIT(3),
			.wakeup_src_z_mask = BIT(0),
			.wakeup_src_y_mask = BIT(1),
			.wakeup_src_x_mask = BIT(2),
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM6DSL_ID,
				.name = ST_LSM6DSL_DEV_NAME,
				.wai = 0x6a,
			}, {
				.hw_id = ST_LSM6DSM_ID,
				.name = ST_LSM6DSM_DEV_NAME,
				.wai = 0x6a,
			}, {
				.hw_id = ST_ISM330DLC_ID,
				.name = ST_ISM330DLC_DEV_NAME,
				.wai = 0x6a,
			}, {
				.hw_id = ST_LSM6DS3TRC_ID,
				.name = ST_LSM6DS3TRC_DEV_NAME,
				.wai = 0x6a,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_len = 6,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_len = 6,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x2 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 4,
			},
		},
		.samples_to_discard = {
			[ST_LSM6DSX_ID_ACC] = {
				.val[0] = {  12500, 1 },
				.val[1] = {  26000, 1 },
				.val[2] = {  52000, 1 },
				.val[3] = { 104000, 2 },
				.val[4] = { 208000, 2 },
				.val[5] = { 416000, 2 },
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.val[0] = {  12500,  2 },
				.val[1] = {  26000,  5 },
				.val[2] = {  52000,  7 },
				.val[3] = { 104000, 12 },
				.val[4] = { 208000, 20 },
				.val[5] = { 416000, 36 },
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0e,
				.mask = BIT(3),
			},
			.lir = {
				.addr = 0x58,
				.mask = BIT(0),
			},
			.irq1_func = {
				.addr = 0x5e,
				.mask = BIT(5),
			},
			.irq2_func = {
				.addr = 0x5f,
				.mask = BIT(5),
			},
			.hla = {
				.addr = 0x12,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x12,
				.mask = BIT(4),
			},
		},
		.decimator = {
			[ST_LSM6DSX_ID_ACC] = {
				.addr = 0x08,
				.mask = GENMASK(2, 0),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.addr = 0x08,
				.mask = GENMASK(5, 3),
			},
			[ST_LSM6DSX_ID_EXT0] = {
				.addr = 0x09,
				.mask = GENMASK(2, 0),
			},
		},
		.fifo_ops = {
			.update_fifo = st_lsm6dsx_update_fifo,
			.read_fifo = st_lsm6dsx_read_fifo,
			.fifo_th = {
				.addr = 0x06,
				.mask = GENMASK(10, 0),
			},
			.fifo_diff = {
				.addr = 0x3a,
				.mask = GENMASK(10, 0),
			},
			.max_size = 682,
			.th_wl = 3, /* 1LSB = 2B */
		},
		.ts_settings = {
			.timer_en = {
				.addr = 0x19,
				.mask = BIT(5),
			},
			.hr_timer = {
				.addr = 0x5c,
				.mask = BIT(4),
			},
			.fifo_en = {
				.addr = 0x07,
				.mask = BIT(7),
			},
			.decimator = {
				.addr = 0x09,
				.mask = GENMASK(5, 3),
			},
		},
		.shub_settings = {
			.page_mux = {
				.addr = 0x01,
				.mask = BIT(7),
			},
			.master_en = {
				.addr = 0x1a,
				.mask = BIT(0),
			},
			.pullup_en = {
				.addr = 0x1a,
				.mask = BIT(3),
			},
			.aux_sens = {
				.addr = 0x04,
				.mask = GENMASK(5, 4),
			},
			.wr_once = {
				.addr = 0x07,
				.mask = BIT(5),
			},
			.emb_func = {
				.addr = 0x19,
				.mask = BIT(2),
			},
			.num_ext_dev = 1,
			.shub_out = {
				.addr = 0x2e,
			},
			.slv0_addr = 0x02,
			.dw_slv0_addr = 0x0e,
			.pause = 0x7,
		},
		.event_settings = {
			.enable_reg = {
				.addr = 0x58,
				.mask = BIT(7),
			},
			.wakeup_reg = {
				.addr = 0x5B,
				.mask = GENMASK(5, 0),
			},
			.wakeup_src_reg = 0x1b,
			.wakeup_src_status_mask = BIT(3),
			.wakeup_src_z_mask = BIT(0),
			.wakeup_src_y_mask = BIT(1),
			.wakeup_src_x_mask = BIT(2),
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM6DSR_ID,
				.name = ST_LSM6DSR_DEV_NAME,
				.wai = 0x6b,
			}, {
				.hw_id = ST_ISM330DHCX_ID,
				.name = ST_ISM330DHCX_DEV_NAME,
				.wai = 0x6b,
			}, {
				.hw_id = ST_LSM6DSRX_ID,
				.name = ST_LSM6DSRX_DEV_NAME,
				.wai = 0x6b,
			}, {
				.hw_id = ST_LSM6DSO_ID,
				.name = ST_LSM6DSO_DEV_NAME,
				.wai = 0x6c,
			}, {
				.hw_id = ST_LSM6DSOX_ID,
				.name = ST_LSM6DSOX_DEV_NAME,
				.wai = 0x6c,
			}, {
				.hw_id = ST_LSM6DST_ID,
				.name = ST_LSM6DST_DEV_NAME,
				.wai = 0x6d,
			}, {
				.hw_id = ST_ASM330LHHX_ID,
				.name = ST_ASM330LHHX_DEV_NAME,
				.wai = 0x6b,
			}, {
				.hw_id = ST_ASM330LHHXG1_ID,
				.name = ST_ASM330LHHXG1_DEV_NAME,
				.wai = 0x6b,
			}, {
				.hw_id = ST_LSM6DSTX_ID,
				.name = ST_LSM6DSTX_DEV_NAME,
				.wai = 0x6d,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.drdy_mask = {
			.addr = 0x13,
			.mask = BIT(3),
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_avl[6] = { 833000, 0x07 },
				.odr_len = 7,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_avl[6] = { 833000, 0x07 },
				.odr_len = 7,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x2 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 4,
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0e,
				.mask = BIT(3),
			},
			.lir = {
				.addr = 0x56,
				.mask = BIT(0),
			},
			.clear_on_read = {
				.addr = 0x56,
				.mask = BIT(6),
			},
			.irq1_func = {
				.addr = 0x5e,
				.mask = BIT(5),
			},
			.irq2_func = {
				.addr = 0x5f,
				.mask = BIT(5),
			},
			.hla = {
				.addr = 0x12,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x12,
				.mask = BIT(4),
			},
		},
		.batch = {
			[ST_LSM6DSX_ID_ACC] = {
				.addr = 0x09,
				.mask = GENMASK(3, 0),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.addr = 0x09,
				.mask = GENMASK(7, 4),
			},
		},
		.fifo_ops = {
			.update_fifo = st_lsm6dsx_update_fifo,
			.read_fifo = st_lsm6dsx_read_tagged_fifo,
			.fifo_th = {
				.addr = 0x07,
				.mask = GENMASK(8, 0),
			},
			.fifo_diff = {
				.addr = 0x3a,
				.mask = GENMASK(9, 0),
			},
			.max_size = 512,
			.th_wl = 1,
		},
		.ts_settings = {
			.timer_en = {
				.addr = 0x19,
				.mask = BIT(5),
			},
			.decimator = {
				.addr = 0x0a,
				.mask = GENMASK(7, 6),
			},
			.freq_fine = 0x63,
		},
		.shub_settings = {
			.page_mux = {
				.addr = 0x01,
				.mask = BIT(6),
			},
			.master_en = {
				.sec_page = true,
				.addr = 0x14,
				.mask = BIT(2),
			},
			.pullup_en = {
				.sec_page = true,
				.addr = 0x14,
				.mask = BIT(3),
			},
			.aux_sens = {
				.addr = 0x14,
				.mask = GENMASK(1, 0),
			},
			.wr_once = {
				.addr = 0x14,
				.mask = BIT(6),
			},
			.num_ext_dev = 3,
			.shub_out = {
				.sec_page = true,
				.addr = 0x02,
			},
			.slv0_addr = 0x15,
			.dw_slv0_addr = 0x21,
			.batch_en = BIT(3),
		},
		.event_settings = {
			.enable_reg = {
				.addr = 0x58,
				.mask = BIT(7),
			},
			.wakeup_reg = {
				.addr = 0x5b,
				.mask = GENMASK(5, 0),
			},
			.wakeup_src_reg = 0x1b,
			.wakeup_src_status_mask = BIT(3),
			.wakeup_src_z_mask = BIT(0),
			.wakeup_src_y_mask = BIT(1),
			.wakeup_src_x_mask = BIT(2),
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_ASM330LHH_ID,
				.name = ST_ASM330LHH_DEV_NAME,
				.wai = 0x6b,
			}, {
				.hw_id = ST_LSM6DSOP_ID,
				.name = ST_LSM6DSOP_DEV_NAME,
				.wai = 0x6c,
			}, {
				.hw_id = ST_ASM330LHB_ID,
				.name = ST_ASM330LHB_DEV_NAME,
				.wai = 0x6b,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.drdy_mask = {
			.addr = 0x13,
			.mask = BIT(3),
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_avl[6] = { 833000, 0x07 },
				.odr_len = 7,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_avl[6] = { 833000, 0x07 },
				.odr_len = 7,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x2 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 4,
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0e,
				.mask = BIT(3),
			},
			.lir = {
				.addr = 0x56,
				.mask = BIT(0),
			},
			.clear_on_read = {
				.addr = 0x56,
				.mask = BIT(6),
			},
			.irq1_func = {
				.addr = 0x5e,
				.mask = BIT(5),
			},
			.irq2_func = {
				.addr = 0x5f,
				.mask = BIT(5),
			},
			.hla = {
				.addr = 0x12,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x12,
				.mask = BIT(4),
			},
		},
		.batch = {
			[ST_LSM6DSX_ID_ACC] = {
				.addr = 0x09,
				.mask = GENMASK(3, 0),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.addr = 0x09,
				.mask = GENMASK(7, 4),
			},
		},
		.fifo_ops = {
			.update_fifo = st_lsm6dsx_update_fifo,
			.read_fifo = st_lsm6dsx_read_tagged_fifo,
			.fifo_th = {
				.addr = 0x07,
				.mask = GENMASK(8, 0),
			},
			.fifo_diff = {
				.addr = 0x3a,
				.mask = GENMASK(9, 0),
			},
			.max_size = 512,
			.th_wl = 1,
		},
		.ts_settings = {
			.timer_en = {
				.addr = 0x19,
				.mask = BIT(5),
			},
			.decimator = {
				.addr = 0x0a,
				.mask = GENMASK(7, 6),
			},
			.freq_fine = 0x63,
		},
		.event_settings = {
			.enable_reg = {
				.addr = 0x58,
				.mask = BIT(7),
			},
			.wakeup_reg = {
				.addr = 0x5B,
				.mask = GENMASK(5, 0),
			},
			.wakeup_src_reg = 0x1b,
			.wakeup_src_status_mask = BIT(3),
			.wakeup_src_z_mask = BIT(0),
			.wakeup_src_y_mask = BIT(1),
			.wakeup_src_x_mask = BIT(2),
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM6DSV_ID,
				.name = ST_LSM6DSV_DEV_NAME,
				.wai = 0x70,
			}, {
				.hw_id = ST_LSM6DSV16X_ID,
				.name = ST_LSM6DSV16X_DEV_NAME,
				.wai = 0x70,
			},
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.drdy_mask = {
			.addr = 0x13,
			.mask = BIT(3),
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 0),
				},
				.odr_avl[0] = {   7500, 0x02 },
				.odr_avl[1] = {  15000, 0x03 },
				.odr_avl[2] = {  30000, 0x04 },
				.odr_avl[3] = {  60000, 0x05 },
				.odr_avl[4] = { 120000, 0x06 },
				.odr_avl[5] = { 240000, 0x07 },
				.odr_avl[6] = { 480000, 0x08 },
				.odr_avl[7] = { 960000, 0x09 },
				.odr_len = 8,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 0),
				},
				.odr_avl[0] = {   7500, 0x02 },
				.odr_avl[1] = {  15000, 0x03 },
				.odr_avl[2] = {  30000, 0x04 },
				.odr_avl[3] = {  60000, 0x05 },
				.odr_avl[4] = { 120000, 0x06 },
				.odr_avl[5] = { 240000, 0x07 },
				.odr_avl[6] = { 480000, 0x08 },
				.odr_avl[7] = { 960000, 0x09 },
				.odr_len = 8,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x17,
					.mask = GENMASK(1, 0),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x1 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x2 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x3 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x15,
					.mask = GENMASK(3, 0),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x1 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x2 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x3 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x4 },
				.fs_len = 4,
			},
		},
		.irq_config = {
			.irq1 = {
				.addr = 0x0d,
				.mask = BIT(3),
			},
			.irq2 = {
				.addr = 0x0e,
				.mask = BIT(3),
			},
			.lir = {
				.addr = 0x56,
				.mask = BIT(0),
			},
			.irq1_func = {
				.addr = 0x5e,
				.mask = BIT(5),
			},
			.irq2_func = {
				.addr = 0x5f,
				.mask = BIT(5),
			},
			.hla = {
				.addr = 0x03,
				.mask = BIT(4),
			},
			.od = {
				.addr = 0x03,
				.mask = BIT(3),
			},
		},
		.batch = {
			[ST_LSM6DSX_ID_ACC] = {
				.addr = 0x09,
				.mask = GENMASK(3, 0),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.addr = 0x09,
				.mask = GENMASK(7, 4),
			},
		},
		.fifo_ops = {
			.update_fifo = st_lsm6dsx_update_fifo,
			.read_fifo = st_lsm6dsx_read_tagged_fifo,
			.fifo_th = {
				.addr = 0x07,
				.mask = GENMASK(7, 0),
			},
			.fifo_diff = {
				.addr = 0x1b,
				.mask = GENMASK(8, 0),
			},
			.max_size = 512,
			.th_wl = 1,
		},
		.ts_settings = {
			.timer_en = {
				.addr = 0x50,
				.mask = BIT(6),
			},
			.decimator = {
				.addr = 0x0a,
				.mask = GENMASK(7, 6),
			},
			.freq_fine = 0x4f,
		},
		.shub_settings = {
			.page_mux = {
				.addr = 0x01,
				.mask = BIT(6),
			},
			.master_en = {
				.sec_page = true,
				.addr = 0x14,
				.mask = BIT(2),
			},
			.pullup_en = {
				.addr = 0x03,
				.mask = BIT(6),
			},
			.aux_sens = {
				.addr = 0x14,
				.mask = GENMASK(1, 0),
			},
			.wr_once = {
				.addr = 0x14,
				.mask = BIT(6),
			},
			.num_ext_dev = 3,
			.shub_out = {
				.sec_page = true,
				.addr = 0x02,
			},
			.slv0_addr = 0x15,
			.dw_slv0_addr = 0x21,
			.batch_en = BIT(3),
		},
		.event_settings = {
			.enable_reg = {
				.addr = 0x50,
				.mask = BIT(7),
			},
			.wakeup_reg = {
				.addr = 0x5b,
				.mask = GENMASK(5, 0),
			},
			.wakeup_src_reg = 0x45,
			.wakeup_src_status_mask = BIT(3),
			.wakeup_src_z_mask = BIT(0),
			.wakeup_src_y_mask = BIT(1),
			.wakeup_src_x_mask = BIT(2),
		},
	},
	{
		.reset = {
			.addr = 0x12,
			.mask = BIT(0),
		},
		.boot = {
			.addr = 0x12,
			.mask = BIT(7),
		},
		.bdu = {
			.addr = 0x12,
			.mask = BIT(6),
		},
		.id = {
			{
				.hw_id = ST_LSM6DSO16IS_ID,
				.name = ST_LSM6DSO16IS_DEV_NAME,
				.wai = 0x22,
			}, {
				.hw_id = ST_ISM330IS_ID,
				.name = ST_ISM330IS_DEV_NAME,
				.wai = 0x22,
			}
		},
		.channels = {
			[ST_LSM6DSX_ID_ACC] = {
				.chan = st_lsm6dsx_acc_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_acc_channels),
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.chan = st_lsm6dsx_gyro_channels,
				.len = ARRAY_SIZE(st_lsm6dsx_gyro_channels),
			},
		},
		.odr_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_avl[6] = { 833000, 0x07 },
				.odr_len = 7,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(7, 4),
				},
				.odr_avl[0] = {  12500, 0x01 },
				.odr_avl[1] = {  26000, 0x02 },
				.odr_avl[2] = {  52000, 0x03 },
				.odr_avl[3] = { 104000, 0x04 },
				.odr_avl[4] = { 208000, 0x05 },
				.odr_avl[5] = { 416000, 0x06 },
				.odr_avl[6] = { 833000, 0x07 },
				.odr_len = 7,
			},
		},
		.fs_table = {
			[ST_LSM6DSX_ID_ACC] = {
				.reg = {
					.addr = 0x10,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_G_TO_M_S_2(61000), 0x0 },
				.fs_avl[1] = { IIO_G_TO_M_S_2(122000), 0x2 },
				.fs_avl[2] = { IIO_G_TO_M_S_2(244000), 0x3 },
				.fs_avl[3] = { IIO_G_TO_M_S_2(488000), 0x1 },
				.fs_len = 4,
			},
			[ST_LSM6DSX_ID_GYRO] = {
				.reg = {
					.addr = 0x11,
					.mask = GENMASK(3, 2),
				},
				.fs_avl[0] = {  IIO_DEGREE_TO_RAD(8750000), 0x0 },
				.fs_avl[1] = { IIO_DEGREE_TO_RAD(17500000), 0x1 },
				.fs_avl[2] = { IIO_DEGREE_TO_RAD(35000000), 0x2 },
				.fs_avl[3] = { IIO_DEGREE_TO_RAD(70000000), 0x3 },
				.fs_len = 4,
			},
		},
		.irq_config = {
			.hla = {
				.addr = 0x12,
				.mask = BIT(5),
			},
			.od = {
				.addr = 0x12,
				.mask = BIT(4),
			},
		},
		.shub_settings = {
			.page_mux = {
				.addr = 0x01,
				.mask = BIT(6),
			},
			.master_en = {
				.sec_page = true,
				.addr = 0x14,
				.mask = BIT(2),
			},
			.pullup_en = {
				.sec_page = true,
				.addr = 0x14,
				.mask = BIT(3),
			},
			.aux_sens = {
				.addr = 0x14,
				.mask = GENMASK(1, 0),
			},
			.wr_once = {
				.addr = 0x14,
				.mask = BIT(6),
			},
			.num_ext_dev = 3,
			.shub_out = {
				.sec_page = true,
				.addr = 0x02,
			},
			.slv0_addr = 0x15,
			.dw_slv0_addr = 0x21,
		},
	},
};

int st_lsm6dsx_set_page(struct st_lsm6dsx_hw *hw, bool enable)
{
	const struct st_lsm6dsx_shub_settings *hub_settings;
	unsigned int data;
	int err;

	hub_settings = &hw->settings->shub_settings;
	data = ST_LSM6DSX_SHIFT_VAL(enable, hub_settings->page_mux.mask);
	err = regmap_update_bits(hw->regmap, hub_settings->page_mux.addr,
				 hub_settings->page_mux.mask, data);
	usleep_range(100, 150);

	return err;
}

static int st_lsm6dsx_check_whoami(struct st_lsm6dsx_hw *hw, int id,
				   const char **name)
{
	int err, i, j, data;

	for (i = 0; i < ARRAY_SIZE(st_lsm6dsx_sensor_settings); i++) {
		for (j = 0; j < ST_LSM6DSX_MAX_ID; j++) {
			if (st_lsm6dsx_sensor_settings[i].id[j].name &&
			    id == st_lsm6dsx_sensor_settings[i].id[j].hw_id)
				break;
		}
		if (j < ST_LSM6DSX_MAX_ID)
			break;
	}

	if (i == ARRAY_SIZE(st_lsm6dsx_sensor_settings)) {
		dev_err(hw->dev, "unsupported hw id [%02x]\n", id);
		return -ENODEV;
	}

	err = regmap_read(hw->regmap, ST_LSM6DSX_REG_WHOAMI_ADDR, &data);
	if (err < 0) {
		dev_err(hw->dev, "failed to read whoami register\n");
		return err;
	}

	if (data != st_lsm6dsx_sensor_settings[i].id[j].wai) {
		dev_err(hw->dev, "unsupported whoami [%02x]\n", data);
		return -ENODEV;
	}

	*name = st_lsm6dsx_sensor_settings[i].id[j].name;
	hw->settings = &st_lsm6dsx_sensor_settings[i];

	return 0;
}

static int st_lsm6dsx_set_full_scale(struct st_lsm6dsx_sensor *sensor,
				     u32 gain)
{
	const struct st_lsm6dsx_fs_table_entry *fs_table;
	unsigned int data;
	int i, err;

	fs_table = &sensor->hw->settings->fs_table[sensor->id];
	for (i = 0; i < fs_table->fs_len; i++) {
		if (fs_table->fs_avl[i].gain == gain)
			break;
	}

	if (i == fs_table->fs_len)
		return -EINVAL;

	data = ST_LSM6DSX_SHIFT_VAL(fs_table->fs_avl[i].val,
				    fs_table->reg.mask);
	err = st_lsm6dsx_update_bits_locked(sensor->hw, fs_table->reg.addr,
					    fs_table->reg.mask, data);
	if (err < 0)
		return err;

	sensor->gain = gain;

	return 0;
}

int st_lsm6dsx_check_odr(struct st_lsm6dsx_sensor *sensor, u32 odr, u8 *val)
{
	const struct st_lsm6dsx_odr_table_entry *odr_table;
	int i;

	odr_table = &sensor->hw->settings->odr_table[sensor->id];
	for (i = 0; i < odr_table->odr_len; i++) {
		/*
		 * ext devices can run at different odr respect to
		 * accel sensor
		 */
		if (odr_table->odr_avl[i].milli_hz >= odr)
			break;
	}

	if (i == odr_table->odr_len)
		return -EINVAL;

	*val = odr_table->odr_avl[i].val;
	return odr_table->odr_avl[i].milli_hz;
}

static int
st_lsm6dsx_check_odr_dependency(struct st_lsm6dsx_hw *hw, u32 odr,
				enum st_lsm6dsx_sensor_id id)
{
	struct st_lsm6dsx_sensor *ref = iio_priv(hw->iio_devs[id]);

	if (odr > 0) {
		if (hw->enable_mask & BIT(id))
			return max_t(u32, ref->odr, odr);
		else
			return odr;
	} else {
		return (hw->enable_mask & BIT(id)) ? ref->odr : 0;
	}
}

static int
st_lsm6dsx_set_odr(struct st_lsm6dsx_sensor *sensor, u32 req_odr)
{
	struct st_lsm6dsx_sensor *ref_sensor = sensor;
	struct st_lsm6dsx_hw *hw = sensor->hw;
	const struct st_lsm6dsx_reg *reg;
	unsigned int data;
	u8 val = 0;
	int err;

	switch (sensor->id) {
	case ST_LSM6DSX_ID_GYRO:
		break;
	case ST_LSM6DSX_ID_EXT0:
	case ST_LSM6DSX_ID_EXT1:
	case ST_LSM6DSX_ID_EXT2:
	case ST_LSM6DSX_ID_ACC: {
		u32 odr;
		int i;

		/*
		 * i2c embedded controller relies on the accelerometer sensor as
		 * bus read/write trigger so we need to enable accel device
		 * at odr = max(accel_odr, ext_odr) in order to properly
		 * communicate with i2c slave devices
		 */
		ref_sensor = iio_priv(hw->iio_devs[ST_LSM6DSX_ID_ACC]);
		for (i = ST_LSM6DSX_ID_ACC; i < ST_LSM6DSX_ID_MAX; i++) {
			if (!hw->iio_devs[i] || i == sensor->id)
				continue;

			odr = st_lsm6dsx_check_odr_dependency(hw, req_odr, i);
			if (odr != req_odr)
				/* device already configured */
				return 0;
		}
		break;
	}
	default: /* should never occur */
		return -EINVAL;
	}

	if (req_odr > 0) {
		err = st_lsm6dsx_check_odr(ref_sensor, req_odr, &val);
		if (err < 0)
			return err;
	}

	reg = &hw->settings->odr_table[ref_sensor->id].reg;
	data = ST_LSM6DSX_SHIFT_VAL(val, reg->mask);
	return st_lsm6dsx_update_bits_locked(hw, reg->addr, reg->mask, data);
}

static int
__st_lsm6dsx_sensor_set_enable(struct st_lsm6dsx_sensor *sensor,
			       bool enable)
{
	struct st_lsm6dsx_hw *hw = sensor->hw;
	u32 odr = enable ? sensor->odr : 0;
	int err;

	err = st_lsm6dsx_set_odr(sensor, odr);
	if (err < 0)
		return err;

	if (enable)
		hw->enable_mask |= BIT(sensor->id);
	else
		hw->enable_mask &= ~BIT(sensor->id);

	return 0;
}

static int
st_lsm6dsx_check_events(struct st_lsm6dsx_sensor *sensor, bool enable)
{
	struct st_lsm6dsx_hw *hw = sensor->hw;

	if (sensor->id == ST_LSM6DSX_ID_GYRO || enable)
		return 0;

	return hw->enable_event;
}

int st_lsm6dsx_sensor_set_enable(struct st_lsm6dsx_sensor *sensor,
				 bool enable)
{
	if (st_lsm6dsx_check_events(sensor, enable))
		return 0;

	return __st_lsm6dsx_sensor_set_enable(sensor, enable);
}

static int st_lsm6dsx_read_oneshot(struct st_lsm6dsx_sensor *sensor,
				   u8 addr, int *val)
{
	struct st_lsm6dsx_hw *hw = sensor->hw;
	int err, delay;
	__le16 data;

	err = st_lsm6dsx_sensor_set_enable(sensor, true);
	if (err < 0)
		return err;

	/*
	 * we need to wait for sensor settling time before
	 * reading data in order to avoid corrupted samples
	 */
	delay = 1000000000 / sensor->odr;
	usleep_range(3 * delay, 4 * delay);

	err = st_lsm6dsx_read_locked(hw, addr, &data, sizeof(data));
	if (err < 0)
		return err;

	if (!hw->enable_event) {
		err = st_lsm6dsx_sensor_set_enable(sensor, false);
		if (err < 0)
			return err;
	}

	*val = (s16)le16_to_cpu(data);

	return IIO_VAL_INT;
}

static int st_lsm6dsx_read_raw(struct iio_dev *iio_dev,
			       struct iio_chan_spec const *ch,
			       int *val, int *val2, long mask)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	int ret;

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		if (!iio_device_claim_direct(iio_dev))
			return -EBUSY;

		ret = st_lsm6dsx_read_oneshot(sensor, ch->address, val);
		iio_device_release_direct(iio_dev);
		break;
	case IIO_CHAN_INFO_SAMP_FREQ:
		*val = sensor->odr / 1000;
		*val2 = (sensor->odr % 1000) * 1000;
		ret = IIO_VAL_INT_PLUS_MICRO;
		break;
	case IIO_CHAN_INFO_SCALE:
		*val = 0;
		*val2 = sensor->gain;
		ret = IIO_VAL_INT_PLUS_NANO;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int st_lsm6dsx_write_raw(struct iio_dev *iio_dev,
				struct iio_chan_spec const *chan,
				int val, int val2, long mask)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	int err = 0;

	if (!iio_device_claim_direct(iio_dev))
		return -EBUSY;

	switch (mask) {
	case IIO_CHAN_INFO_SCALE:
		err = st_lsm6dsx_set_full_scale(sensor, val2);
		break;
	case IIO_CHAN_INFO_SAMP_FREQ: {
		u8 data;

		val = val * 1000 + val2 / 1000;
		val = st_lsm6dsx_check_odr(sensor, val, &data);
		if (val < 0)
			err = val;
		else
			sensor->odr = val;
		break;
	}
	default:
		err = -EINVAL;
		break;
	}

	iio_device_release_direct(iio_dev);

	return err;
}

static int st_lsm6dsx_event_setup(struct st_lsm6dsx_hw *hw, bool state)
{
	const struct st_lsm6dsx_reg *reg;
	unsigned int data;
	int err;

	if (!hw->settings->irq_config.irq1_func.addr)
		return -ENOTSUPP;

	reg = &hw->settings->event_settings.enable_reg;
	if (reg->addr) {
		data = ST_LSM6DSX_SHIFT_VAL(state, reg->mask);
		err = st_lsm6dsx_update_bits_locked(hw, reg->addr,
						    reg->mask, data);
		if (err < 0)
			return err;
	}

	/* Enable wakeup interrupt */
	data = ST_LSM6DSX_SHIFT_VAL(state, hw->irq_routing->mask);
	return st_lsm6dsx_update_bits_locked(hw, hw->irq_routing->addr,
					     hw->irq_routing->mask, data);
}

static int st_lsm6dsx_read_event(struct iio_dev *iio_dev,
				 const struct iio_chan_spec *chan,
				 enum iio_event_type type,
				 enum iio_event_direction dir,
				 enum iio_event_info info,
				 int *val, int *val2)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	struct st_lsm6dsx_hw *hw = sensor->hw;

	if (type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	*val2 = 0;
	*val = hw->event_threshold;

	return IIO_VAL_INT;
}

static int
st_lsm6dsx_write_event(struct iio_dev *iio_dev,
		       const struct iio_chan_spec *chan,
		       enum iio_event_type type,
		       enum iio_event_direction dir,
		       enum iio_event_info info,
		       int val, int val2)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	struct st_lsm6dsx_hw *hw = sensor->hw;
	const struct st_lsm6dsx_reg *reg;
	unsigned int data;
	int err;

	if (type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	if (val < 0 || val > 31)
		return -EINVAL;

	reg = &hw->settings->event_settings.wakeup_reg;
	data = ST_LSM6DSX_SHIFT_VAL(val, reg->mask);
	err = st_lsm6dsx_update_bits_locked(hw, reg->addr,
					    reg->mask, data);
	if (err < 0)
		return -EINVAL;

	hw->event_threshold = val;

	return 0;
}

static int
st_lsm6dsx_read_event_config(struct iio_dev *iio_dev,
			     const struct iio_chan_spec *chan,
			     enum iio_event_type type,
			     enum iio_event_direction dir)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	struct st_lsm6dsx_hw *hw = sensor->hw;

	if (type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	return !!(hw->enable_event & BIT(chan->channel2));
}

static int
st_lsm6dsx_write_event_config(struct iio_dev *iio_dev,
			      const struct iio_chan_spec *chan,
			      enum iio_event_type type,
			      enum iio_event_direction dir, bool state)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	struct st_lsm6dsx_hw *hw = sensor->hw;
	u8 enable_event;
	int err;

	if (type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	if (state) {
		enable_event = hw->enable_event | BIT(chan->channel2);

		/* do not enable events if they are already enabled */
		if (hw->enable_event)
			goto out;
	} else {
		enable_event = hw->enable_event & ~BIT(chan->channel2);

		/* only turn off sensor if no events is enabled */
		if (enable_event)
			goto out;
	}

	/* stop here if no changes have been made */
	if (hw->enable_event == enable_event)
		return 0;

	err = st_lsm6dsx_event_setup(hw, state);
	if (err < 0)
		return err;

	mutex_lock(&hw->conf_lock);
	if (enable_event || !(hw->fifo_mask & BIT(sensor->id)))
		err = __st_lsm6dsx_sensor_set_enable(sensor, state);
	mutex_unlock(&hw->conf_lock);
	if (err < 0)
		return err;

out:
	hw->enable_event = enable_event;

	return 0;
}

int st_lsm6dsx_set_watermark(struct iio_dev *iio_dev, unsigned int val)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	struct st_lsm6dsx_hw *hw = sensor->hw;
	int err;

	val = clamp_val(val, 1, hw->settings->fifo_ops.max_size);

	mutex_lock(&hw->conf_lock);

	err = st_lsm6dsx_update_watermark(sensor, val);

	mutex_unlock(&hw->conf_lock);

	if (err < 0)
		return err;

	sensor->watermark = val;

	return 0;
}

static ssize_t
st_lsm6dsx_sysfs_sampling_frequency_avail(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(dev_to_iio_dev(dev));
	const struct st_lsm6dsx_odr_table_entry *odr_table;
	int i, len = 0;

	odr_table = &sensor->hw->settings->odr_table[sensor->id];
	for (i = 0; i < odr_table->odr_len; i++)
		len += scnprintf(buf + len, PAGE_SIZE - len, "%d.%03d ",
				 odr_table->odr_avl[i].milli_hz / 1000,
				 odr_table->odr_avl[i].milli_hz % 1000);
	buf[len - 1] = '\n';

	return len;
}

static ssize_t st_lsm6dsx_sysfs_scale_avail(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(dev_to_iio_dev(dev));
	const struct st_lsm6dsx_fs_table_entry *fs_table;
	struct st_lsm6dsx_hw *hw = sensor->hw;
	int i, len = 0;

	fs_table = &hw->settings->fs_table[sensor->id];
	for (i = 0; i < fs_table->fs_len; i++)
		len += scnprintf(buf + len, PAGE_SIZE - len, "0.%09u ",
				 fs_table->fs_avl[i].gain);
	buf[len - 1] = '\n';

	return len;
}

static int st_lsm6dsx_write_raw_get_fmt(struct iio_dev *indio_dev,
					struct iio_chan_spec const *chan,
					long mask)
{
	switch (mask) {
	case IIO_CHAN_INFO_SCALE:
		switch (chan->type) {
		case IIO_ANGL_VEL:
		case IIO_ACCEL:
			return IIO_VAL_INT_PLUS_NANO;
		default:
			return IIO_VAL_INT_PLUS_MICRO;
		}
	default:
		return IIO_VAL_INT_PLUS_MICRO;
	}
}

static IIO_DEV_ATTR_SAMP_FREQ_AVAIL(st_lsm6dsx_sysfs_sampling_frequency_avail);
static IIO_DEVICE_ATTR(in_accel_scale_available, 0444,
		       st_lsm6dsx_sysfs_scale_avail, NULL, 0);
static IIO_DEVICE_ATTR(in_anglvel_scale_available, 0444,
		       st_lsm6dsx_sysfs_scale_avail, NULL, 0);

static struct attribute *st_lsm6dsx_acc_attributes[] = {
	&iio_dev_attr_sampling_frequency_available.dev_attr.attr,
	&iio_dev_attr_in_accel_scale_available.dev_attr.attr,
	NULL,
};

static const struct attribute_group st_lsm6dsx_acc_attribute_group = {
	.attrs = st_lsm6dsx_acc_attributes,
};

static const struct iio_info st_lsm6dsx_acc_info = {
	.attrs = &st_lsm6dsx_acc_attribute_group,
	.read_raw = st_lsm6dsx_read_raw,
	.write_raw = st_lsm6dsx_write_raw,
	.read_event_value = st_lsm6dsx_read_event,
	.write_event_value = st_lsm6dsx_write_event,
	.read_event_config = st_lsm6dsx_read_event_config,
	.write_event_config = st_lsm6dsx_write_event_config,
	.hwfifo_set_watermark = st_lsm6dsx_set_watermark,
	.write_raw_get_fmt = st_lsm6dsx_write_raw_get_fmt,
};

static struct attribute *st_lsm6dsx_gyro_attributes[] = {
	&iio_dev_attr_sampling_frequency_available.dev_attr.attr,
	&iio_dev_attr_in_anglvel_scale_available.dev_attr.attr,
	NULL,
};

static const struct attribute_group st_lsm6dsx_gyro_attribute_group = {
	.attrs = st_lsm6dsx_gyro_attributes,
};

static const struct iio_info st_lsm6dsx_gyro_info = {
	.attrs = &st_lsm6dsx_gyro_attribute_group,
	.read_raw = st_lsm6dsx_read_raw,
	.write_raw = st_lsm6dsx_write_raw,
	.hwfifo_set_watermark = st_lsm6dsx_set_watermark,
	.write_raw_get_fmt = st_lsm6dsx_write_raw_get_fmt,
};

static int
st_lsm6dsx_get_drdy_reg(struct st_lsm6dsx_hw *hw,
			const struct st_lsm6dsx_reg **drdy_reg)
{
	struct device *dev = hw->dev;
	const struct st_sensors_platform_data *pdata = dev_get_platdata(dev);
	int err = 0, drdy_pin;

	if (device_property_read_u32(dev, "st,drdy-int-pin", &drdy_pin) < 0)
		drdy_pin = pdata ? pdata->drdy_int_pin : 1;

	switch (drdy_pin) {
	case 1:
		hw->irq_routing = &hw->settings->irq_config.irq1_func;
		*drdy_reg = &hw->settings->irq_config.irq1;
		break;
	case 2:
		hw->irq_routing = &hw->settings->irq_config.irq2_func;
		*drdy_reg = &hw->settings->irq_config.irq2;
		break;
	default:
		dev_err(hw->dev, "unsupported data ready pin\n");
		err = -EINVAL;
		break;
	}

	return err;
}

static int st_lsm6dsx_init_shub(struct st_lsm6dsx_hw *hw)
{
	const struct st_lsm6dsx_shub_settings *hub_settings;
	struct device *dev = hw->dev;
	const struct st_sensors_platform_data *pdata = dev_get_platdata(dev);
	unsigned int data;
	int err = 0;

	hub_settings = &hw->settings->shub_settings;

	if (device_property_read_bool(dev, "st,pullups") ||
	    (pdata && pdata->pullups)) {
		if (hub_settings->pullup_en.sec_page) {
			err = st_lsm6dsx_set_page(hw, true);
			if (err < 0)
				return err;
		}

		data = ST_LSM6DSX_SHIFT_VAL(1, hub_settings->pullup_en.mask);
		err = regmap_update_bits(hw->regmap,
					 hub_settings->pullup_en.addr,
					 hub_settings->pullup_en.mask, data);

		if (hub_settings->pullup_en.sec_page)
			st_lsm6dsx_set_page(hw, false);

		if (err < 0)
			return err;
	}

	if (hub_settings->aux_sens.addr) {
		/* configure aux sensors */
		err = st_lsm6dsx_set_page(hw, true);
		if (err < 0)
			return err;

		data = ST_LSM6DSX_SHIFT_VAL(3, hub_settings->aux_sens.mask);
		err = regmap_update_bits(hw->regmap,
					 hub_settings->aux_sens.addr,
					 hub_settings->aux_sens.mask, data);

		st_lsm6dsx_set_page(hw, false);

		if (err < 0)
			return err;
	}

	if (hub_settings->emb_func.addr) {
		data = ST_LSM6DSX_SHIFT_VAL(1, hub_settings->emb_func.mask);
		err = regmap_update_bits(hw->regmap,
					 hub_settings->emb_func.addr,
					 hub_settings->emb_func.mask, data);
	}

	return err;
}

static int st_lsm6dsx_init_hw_timer(struct st_lsm6dsx_hw *hw)
{
	const struct st_lsm6dsx_hw_ts_settings *ts_settings;
	int err, val;

	ts_settings = &hw->settings->ts_settings;
	/* enable hw timestamp generation if necessary */
	if (ts_settings->timer_en.addr) {
		val = ST_LSM6DSX_SHIFT_VAL(1, ts_settings->timer_en.mask);
		err = regmap_update_bits(hw->regmap,
					 ts_settings->timer_en.addr,
					 ts_settings->timer_en.mask, val);
		if (err < 0)
			return err;
	}

	/* enable high resolution for hw ts timer if necessary */
	if (ts_settings->hr_timer.addr) {
		val = ST_LSM6DSX_SHIFT_VAL(1, ts_settings->hr_timer.mask);
		err = regmap_update_bits(hw->regmap,
					 ts_settings->hr_timer.addr,
					 ts_settings->hr_timer.mask, val);
		if (err < 0)
			return err;
	}

	/* enable ts queueing in FIFO if necessary */
	if (ts_settings->fifo_en.addr) {
		val = ST_LSM6DSX_SHIFT_VAL(1, ts_settings->fifo_en.mask);
		err = regmap_update_bits(hw->regmap,
					 ts_settings->fifo_en.addr,
					 ts_settings->fifo_en.mask, val);
		if (err < 0)
			return err;
	}

	/* calibrate timestamp sensitivity */
	hw->ts_gain = ST_LSM6DSX_TS_SENSITIVITY;
	if (ts_settings->freq_fine) {
		err = regmap_read(hw->regmap, ts_settings->freq_fine, &val);
		if (err < 0)
			return err;

		/*
		 * linearize the AN5192 formula:
		 * 1 / (1 + x) ~= 1 - x (Taylor’s Series)
		 * ttrim[s] = 1 / (40000 * (1 + 0.0015 * val))
		 * ttrim[ns] ~= 25000 - 37.5 * val
		 * ttrim[ns] ~= 25000 - (37500 * val) / 1000
		 */
		hw->ts_gain -= ((s8)val * 37500) / 1000;
	}

	return 0;
}

static int st_lsm6dsx_reset_device(struct st_lsm6dsx_hw *hw)
{
	const struct st_lsm6dsx_reg *reg;
	int err;

	/*
	 * flush hw FIFO before device reset in order to avoid
	 * possible races on interrupt line 1. If the first interrupt
	 * line is asserted during hw reset the device will work in
	 * I3C-only mode (if it is supported)
	 */
	err = st_lsm6dsx_flush_fifo(hw);
	if (err < 0 && err != -ENOTSUPP)
		return err;

	/* device sw reset */
	reg = &hw->settings->reset;
	err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
				 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
	if (err < 0)
		return err;

	msleep(50);

	/* reload trimming parameter */
	reg = &hw->settings->boot;
	err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
				 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
	if (err < 0)
		return err;

	msleep(50);

	return 0;
}

static int st_lsm6dsx_init_device(struct st_lsm6dsx_hw *hw)
{
	const struct st_lsm6dsx_reg *reg;
	int err;

	err = st_lsm6dsx_reset_device(hw);
	if (err < 0)
		return err;

	/* enable Block Data Update */
	reg = &hw->settings->bdu;
	err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
				 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
	if (err < 0)
		return err;

	/* enable FIFO watermak interrupt */
	err = st_lsm6dsx_get_drdy_reg(hw, &reg);
	if (err < 0)
		return err;

	err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
				 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
	if (err < 0)
		return err;

	/* enable Latched interrupts for device events */
	if (hw->settings->irq_config.lir.addr) {
		reg = &hw->settings->irq_config.lir;
		err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
					 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
		if (err < 0)
			return err;

		/* enable clear on read for latched interrupts */
		if (hw->settings->irq_config.clear_on_read.addr) {
			reg = &hw->settings->irq_config.clear_on_read;
			err = regmap_update_bits(hw->regmap,
					reg->addr, reg->mask,
					ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
			if (err < 0)
				return err;
		}
	}

	/* enable drdy-mas if available */
	if (hw->settings->drdy_mask.addr) {
		reg = &hw->settings->drdy_mask;
		err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
					 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
		if (err < 0)
			return err;
	}

	err = st_lsm6dsx_init_shub(hw);
	if (err < 0)
		return err;

	return st_lsm6dsx_init_hw_timer(hw);
}

static struct iio_dev *st_lsm6dsx_alloc_iiodev(struct st_lsm6dsx_hw *hw,
					       enum st_lsm6dsx_sensor_id id,
					       const char *name)
{
	struct st_lsm6dsx_sensor *sensor;
	struct iio_dev *iio_dev;

	iio_dev = devm_iio_device_alloc(hw->dev, sizeof(*sensor));
	if (!iio_dev)
		return NULL;

	iio_dev->modes = INDIO_DIRECT_MODE;
	iio_dev->available_scan_masks = st_lsm6dsx_available_scan_masks;
	iio_dev->channels = hw->settings->channels[id].chan;
	iio_dev->num_channels = hw->settings->channels[id].len;

	sensor = iio_priv(iio_dev);
	sensor->id = id;
	sensor->hw = hw;
	sensor->odr = hw->settings->odr_table[id].odr_avl[0].milli_hz;
	sensor->gain = hw->settings->fs_table[id].fs_avl[0].gain;
	sensor->watermark = 1;

	switch (id) {
	case ST_LSM6DSX_ID_ACC:
		iio_dev->info = &st_lsm6dsx_acc_info;
		scnprintf(sensor->name, sizeof(sensor->name), "%s_accel",
			  name);
		break;
	case ST_LSM6DSX_ID_GYRO:
		iio_dev->info = &st_lsm6dsx_gyro_info;
		scnprintf(sensor->name, sizeof(sensor->name), "%s_gyro",
			  name);
		break;
	default:
		return NULL;
	}
	iio_dev->name = sensor->name;

	return iio_dev;
}

static bool
st_lsm6dsx_report_motion_event(struct st_lsm6dsx_hw *hw)
{
	const struct st_lsm6dsx_event_settings *event_settings;
	int err, data;
	s64 timestamp;

	if (!hw->enable_event)
		return false;

	event_settings = &hw->settings->event_settings;
	err = st_lsm6dsx_read_locked(hw, event_settings->wakeup_src_reg,
				     &data, sizeof(data));
	if (err < 0)
		return false;

	timestamp = iio_get_time_ns(hw->iio_devs[ST_LSM6DSX_ID_ACC]);
	if ((data & hw->settings->event_settings.wakeup_src_z_mask) &&
	    (hw->enable_event & BIT(IIO_MOD_Z)))
		iio_push_event(hw->iio_devs[ST_LSM6DSX_ID_ACC],
			       IIO_MOD_EVENT_CODE(IIO_ACCEL,
						  0,
						  IIO_MOD_Z,
						  IIO_EV_TYPE_THRESH,
						  IIO_EV_DIR_EITHER),
						  timestamp);

	if ((data & hw->settings->event_settings.wakeup_src_y_mask) &&
	    (hw->enable_event & BIT(IIO_MOD_Y)))
		iio_push_event(hw->iio_devs[ST_LSM6DSX_ID_ACC],
			       IIO_MOD_EVENT_CODE(IIO_ACCEL,
						  0,
						  IIO_MOD_Y,
						  IIO_EV_TYPE_THRESH,
						  IIO_EV_DIR_EITHER),
						  timestamp);

	if ((data & hw->settings->event_settings.wakeup_src_x_mask) &&
	    (hw->enable_event & BIT(IIO_MOD_X)))
		iio_push_event(hw->iio_devs[ST_LSM6DSX_ID_ACC],
			       IIO_MOD_EVENT_CODE(IIO_ACCEL,
						  0,
						  IIO_MOD_X,
						  IIO_EV_TYPE_THRESH,
						  IIO_EV_DIR_EITHER),
						  timestamp);

	return data & event_settings->wakeup_src_status_mask;
}

static irqreturn_t st_lsm6dsx_handler_thread(int irq, void *private)
{
	struct st_lsm6dsx_hw *hw = private;
	int fifo_len = 0, len;
	bool event;

	event = st_lsm6dsx_report_motion_event(hw);

	if (!hw->settings->fifo_ops.read_fifo)
		return event ? IRQ_HANDLED : IRQ_NONE;

	/*
	 * If we are using edge IRQs, new samples can arrive while
	 * processing current interrupt since there are no hw
	 * guarantees the irq line stays "low" long enough to properly
	 * detect the new interrupt. In this case the new sample will
	 * be missed.
	 * Polling FIFO status register allow us to read new
	 * samples even if the interrupt arrives while processing
	 * previous data and the timeslot where the line is "low" is
	 * too short to be properly detected.
	 */
	do {
		mutex_lock(&hw->fifo_lock);
		len = hw->settings->fifo_ops.read_fifo(hw);
		mutex_unlock(&hw->fifo_lock);

		if (len > 0)
			fifo_len += len;
	} while (len > 0);

	return fifo_len || event ? IRQ_HANDLED : IRQ_NONE;
}

static irqreturn_t st_lsm6dsx_sw_trigger_handler_thread(int irq,
							void *private)
{
	struct iio_poll_func *pf = private;
	struct iio_dev *iio_dev = pf->indio_dev;
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);
	struct st_lsm6dsx_hw *hw = sensor->hw;

	if (sensor->id == ST_LSM6DSX_ID_EXT0 ||
	    sensor->id == ST_LSM6DSX_ID_EXT1 ||
	    sensor->id == ST_LSM6DSX_ID_EXT2)
		st_lsm6dsx_shub_read_output(hw,
					    (u8 *)hw->scan[sensor->id].channels,
					    sizeof(hw->scan[sensor->id].channels));
	else
		st_lsm6dsx_read_locked(hw, iio_dev->channels[0].address,
				       hw->scan[sensor->id].channels,
				       sizeof(hw->scan[sensor->id].channels));

	iio_push_to_buffers_with_timestamp(iio_dev, &hw->scan[sensor->id],
					   iio_get_time_ns(iio_dev));
	iio_trigger_notify_done(iio_dev->trig);

	return IRQ_HANDLED;
}

static int st_lsm6dsx_irq_setup(struct st_lsm6dsx_hw *hw)
{
	const struct st_lsm6dsx_reg *reg;
	struct device *dev = hw->dev;
	const struct st_sensors_platform_data *pdata = dev_get_platdata(dev);
	unsigned long irq_type;
	bool irq_active_low;
	int err;

	irq_type = irq_get_trigger_type(hw->irq);
	switch (irq_type) {
	case IRQF_TRIGGER_HIGH:
	case IRQF_TRIGGER_RISING:
		irq_active_low = false;
		break;
	case IRQF_TRIGGER_LOW:
	case IRQF_TRIGGER_FALLING:
		irq_active_low = true;
		break;
	default:
		dev_info(hw->dev, "mode %lx unsupported\n", irq_type);
		return -EINVAL;
	}

	reg = &hw->settings->irq_config.hla;
	err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
				 ST_LSM6DSX_SHIFT_VAL(irq_active_low,
						      reg->mask));
	if (err < 0)
		return err;

	if (device_property_read_bool(dev, "drive-open-drain") ||
	    (pdata && pdata->open_drain)) {
		reg = &hw->settings->irq_config.od;
		err = regmap_update_bits(hw->regmap, reg->addr, reg->mask,
					 ST_LSM6DSX_SHIFT_VAL(1, reg->mask));
		if (err < 0)
			return err;

		irq_type |= IRQF_SHARED;
	}

	err = devm_request_threaded_irq(hw->dev, hw->irq,
					NULL,
					st_lsm6dsx_handler_thread,
					irq_type | IRQF_ONESHOT,
					"lsm6dsx", hw);
	if (err) {
		dev_err(hw->dev, "failed to request trigger irq %d\n",
			hw->irq);
		return err;
	}

	return 0;
}

static int st_lsm6dsx_sw_buffer_preenable(struct iio_dev *iio_dev)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);

	return st_lsm6dsx_device_set_enable(sensor, true);
}

static int st_lsm6dsx_sw_buffer_postdisable(struct iio_dev *iio_dev)
{
	struct st_lsm6dsx_sensor *sensor = iio_priv(iio_dev);

	return st_lsm6dsx_device_set_enable(sensor, false);
}

static const struct iio_buffer_setup_ops st_lsm6dsx_sw_buffer_ops = {
	.preenable = st_lsm6dsx_sw_buffer_preenable,
	.postdisable = st_lsm6dsx_sw_buffer_postdisable,
};

static int st_lsm6dsx_sw_buffers_setup(struct st_lsm6dsx_hw *hw)
{
	int i;

	for (i = 0; i < ST_LSM6DSX_ID_MAX; i++) {
		int err;

		if (!hw->iio_devs[i])
			continue;

		err = devm_iio_triggered_buffer_setup(hw->dev,
					hw->iio_devs[i], NULL,
					st_lsm6dsx_sw_trigger_handler_thread,
					&st_lsm6dsx_sw_buffer_ops);
		if (err)
			return err;
	}

	return 0;
}

static int st_lsm6dsx_init_regulators(struct device *dev)
{
	/* vdd-vddio power regulators */
	static const char * const regulators[] = { "vdd", "vddio" };
	int err;

	err = devm_regulator_bulk_get_enable(dev, ARRAY_SIZE(regulators),
					     regulators);
	if (err)
		return dev_err_probe(dev, err, "failed to enable regulators\n");

	msleep(50);

	return 0;
}

int st_lsm6dsx_probe(struct device *dev, int irq, int hw_id,
		     struct regmap *regmap)
{
	const struct st_sensors_platform_data *pdata = dev_get_platdata(dev);
	const struct st_lsm6dsx_shub_settings *hub_settings;
	struct st_lsm6dsx_hw *hw;
	const char *name = NULL;
	int i, err;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;

	dev_set_drvdata(dev, hw);

	mutex_init(&hw->fifo_lock);
	mutex_init(&hw->conf_lock);
	mutex_init(&hw->page_lock);

	err = st_lsm6dsx_init_regulators(dev);
	if (err)
		return err;

	hw->buff = devm_kzalloc(dev, ST_LSM6DSX_BUFF_SIZE, GFP_KERNEL);
	if (!hw->buff)
		return -ENOMEM;

	hw->dev = dev;
	hw->irq = irq;
	hw->regmap = regmap;

	err = st_lsm6dsx_check_whoami(hw, hw_id, &name);
	if (err < 0)
		return err;

	for (i = 0; i < ST_LSM6DSX_ID_EXT0; i++) {
		hw->iio_devs[i] = st_lsm6dsx_alloc_iiodev(hw, i, name);
		if (!hw->iio_devs[i])
			return -ENOMEM;
	}

	err = st_lsm6dsx_init_device(hw);
	if (err < 0)
		return err;

	hub_settings = &hw->settings->shub_settings;
	if (hub_settings->master_en.addr &&
	    !device_property_read_bool(dev, "st,disable-sensor-hub")) {
		err = st_lsm6dsx_shub_probe(hw, name);
		if (err < 0)
			return err;
	}

	if (hw->irq > 0) {
		err = st_lsm6dsx_irq_setup(hw);
		if (err < 0)
			return err;

		err = st_lsm6dsx_fifo_setup(hw);
		if (err < 0)
			return err;
	}

	if (!hw->irq || !hw->settings->fifo_ops.read_fifo) {
		/*
		 * Rely on sw triggers (e.g. hr-timers) if irq pin is not
		 * connected of if the device does not support HW FIFO
		 */
		err = st_lsm6dsx_sw_buffers_setup(hw);
		if (err)
			return err;
	}

	if (!iio_read_acpi_mount_matrix(hw->dev, &hw->orientation, "ROTM")) {
		err = iio_read_mount_matrix(hw->dev, &hw->orientation);
		if (err)
			return err;
	}

	for (i = 0; i < ST_LSM6DSX_ID_MAX; i++) {
		if (!hw->iio_devs[i])
			continue;

		err = devm_iio_device_register(hw->dev, hw->iio_devs[i]);
		if (err)
			return err;
	}

	if (device_property_read_bool(dev, "wakeup-source") ||
	    (pdata && pdata->wakeup_source)) {
		err = devm_device_init_wakeup(dev);
		if (err)
			return dev_err_probe(dev, err, "Failed to init wakeup\n");
	}

	return 0;
}
EXPORT_SYMBOL_NS(st_lsm6dsx_probe, "IIO_LSM6DSX");

static int st_lsm6dsx_suspend(struct device *dev)
{
	struct st_lsm6dsx_hw *hw = dev_get_drvdata(dev);
	struct st_lsm6dsx_sensor *sensor;
	int i, err = 0;

	for (i = 0; i < ST_LSM6DSX_ID_MAX; i++) {
		if (!hw->iio_devs[i])
			continue;

		sensor = iio_priv(hw->iio_devs[i]);
		if (!(hw->enable_mask & BIT(sensor->id)))
			continue;

		if (device_may_wakeup(dev) &&
		    sensor->id == ST_LSM6DSX_ID_ACC && hw->enable_event) {
			/* Enable wake from IRQ */
			enable_irq_wake(hw->irq);
			continue;
		}

		err = st_lsm6dsx_device_set_enable(sensor, false);
		if (err < 0)
			return err;

		hw->suspend_mask |= BIT(sensor->id);
	}

	if (hw->fifo_mask)
		err = st_lsm6dsx_flush_fifo(hw);

	return err;
}

static int st_lsm6dsx_resume(struct device *dev)
{
	struct st_lsm6dsx_hw *hw = dev_get_drvdata(dev);
	struct st_lsm6dsx_sensor *sensor;
	int i, err = 0;

	for (i = 0; i < ST_LSM6DSX_ID_MAX; i++) {
		if (!hw->iio_devs[i])
			continue;

		sensor = iio_priv(hw->iio_devs[i]);
		if (device_may_wakeup(dev) &&
		    sensor->id == ST_LSM6DSX_ID_ACC && hw->enable_event)
			disable_irq_wake(hw->irq);

		if (!(hw->suspend_mask & BIT(sensor->id)))
			continue;

		err = st_lsm6dsx_device_set_enable(sensor, true);
		if (err < 0)
			return err;

		hw->suspend_mask &= ~BIT(sensor->id);
	}

	if (hw->fifo_mask)
		err = st_lsm6dsx_resume_fifo(hw);

	return err;
}

EXPORT_NS_SIMPLE_DEV_PM_OPS(st_lsm6dsx_pm_ops, st_lsm6dsx_suspend,
			    st_lsm6dsx_resume, IIO_LSM6DSX);

MODULE_AUTHOR("Lorenzo Bianconi <lorenzo.bianconi@st.com>");
MODULE_AUTHOR("Denis Ciocca <denis.ciocca@st.com>");
MODULE_DESCRIPTION("STMicroelectronics st_lsm6dsx driver");
MODULE_LICENSE("GPL v2");
