/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * C global declaration parser for genksyms.
 * Copyright 1996, 1997 Linux International.
 *
 * New implementation contributed by Richard Henderson <rth@tamu.edu>
 * Based on original work by Bjorn Ekwall <bj0rn@blox.se>
 *
 * This file is part of the Linux modutils.
 */

%{

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "genksyms.h"

static int is_typedef;
static int is_extern;
static char *current_name;
static struct string_list *decl_spec;

static void yyerror(const char *);

static inline void
remove_node(struct string_list **p)
{
  struct string_list *node = *p;
  *p = node->next;
  free_node(node);
}

static inline void
remove_list(struct string_list **pb, struct string_list **pe)
{
  struct string_list *b = *pb, *e = *pe;
  *pb = e;
  free_list(b, e);
}

/* Record definition of a struct/union/enum */
static void record_compound(struct string_list **keyw,
		       struct string_list **ident,
		       struct string_list **body,
		       enum symbol_type type)
{
	struct string_list *b = *body, *i = *ident, *r;

	if (i->in_source_file) {
		remove_node(keyw);
		(*ident)->tag = type;
		remove_list(body, ident);
		return;
	}
	r = copy_node(i); r->tag = type;
	r->next = (*keyw)->next; *body = r; (*keyw)->next = NULL;
	add_symbol(i->string, type, b, is_extern);
}

%}

%token ASM_KEYW
%token ATTRIBUTE_KEYW
%token AUTO_KEYW
%token BOOL_KEYW
%token BUILTIN_INT_KEYW
%token CHAR_KEYW
%token CONST_KEYW
%token DOUBLE_KEYW
%token ENUM_KEYW
%token EXTERN_KEYW
%token EXTENSION_KEYW
%token FLOAT_KEYW
%token INLINE_KEYW
%token INT_KEYW
%token LONG_KEYW
%token REGISTER_KEYW
%token RESTRICT_KEYW
%token SHORT_KEYW
%token SIGNED_KEYW
%token STATIC_KEYW
%token STATIC_ASSERT_KEYW
%token STRUCT_KEYW
%token TYPEDEF_KEYW
%token UNION_KEYW
%token UNSIGNED_KEYW
%token VOID_KEYW
%token VOLATILE_KEYW
%token TYPEOF_KEYW
%token VA_LIST_KEYW

%token X86_SEG_KEYW

%token EXPORT_SYMBOL_KEYW

%token ASM_PHRASE
%token ATTRIBUTE_PHRASE
%token TYPEOF_PHRASE
%token BRACE_PHRASE
%token BRACKET_PHRASE
%token EXPRESSION_PHRASE
%token STATIC_ASSERT_PHRASE

%token CHAR
%token DOTS
%token IDENT
%token INT
%token REAL
%token STRING
%token TYPE
%token OTHER
%token FILENAME

%%

declaration_seq:
	declaration
	| declaration_seq declaration
	;

declaration:
	{ is_typedef = 0; is_extern = 0; current_name = NULL; decl_spec = NULL; }
	declaration1
	{ free_list(*$2, NULL); *$2 = NULL; }
	;

declaration1:
	EXTENSION_KEYW TYPEDEF_KEYW { is_typedef = 1; } simple_declaration
		{ $$ = $4; }
	| TYPEDEF_KEYW { is_typedef = 1; } simple_declaration
		{ $$ = $3; }
	| simple_declaration
	| function_definition
	| asm_definition
	| export_definition
	| static_assert
	| error ';'				{ $$ = $2; }
	| error '}'				{ $$ = $2; }
	;

simple_declaration:
	decl_specifier_seq_opt init_declarator_list_opt ';'
		{ if (current_name) {
		    struct string_list *decl = (*$3)->next;
		    (*$3)->next = NULL;
		    add_symbol(current_name,
			       is_typedef ? SYM_TYPEDEF : SYM_NORMAL,
			       decl, is_extern);
		    current_name = NULL;
		  }
		  $$ = $3;
		  dont_want_type_specifier = false;
		}
	;

init_declarator_list_opt:
	/* empty */			{ $$ = NULL; }
	| init_declarator_list		{ free_list(decl_spec, NULL); $$ = $1; }
	;

init_declarator_list:
	init_declarator
		{ struct string_list *decl = *$1;
		  *$1 = NULL;

		  /* avoid sharing among multiple init_declarators */
		  if (decl_spec)
		    decl_spec = copy_list_range(decl_spec, NULL);

		  add_symbol(current_name,
			     is_typedef ? SYM_TYPEDEF : SYM_NORMAL, decl, is_extern);
		  current_name = NULL;
		  $$ = $1;
		  dont_want_type_specifier = true;
		}
	| init_declarator_list ',' attribute_opt init_declarator
		{ struct string_list *decl = *$4;
		  *$4 = NULL;
		  free_list(*$2, NULL);
		  *$2 = decl_spec;

		  /* avoid sharing among multiple init_declarators */
		  if (decl_spec)
		    decl_spec = copy_list_range(decl_spec, NULL);

		  add_symbol(current_name,
			     is_typedef ? SYM_TYPEDEF : SYM_NORMAL, decl, is_extern);
		  current_name = NULL;
		  $$ = $4;
		  dont_want_type_specifier = true;
		}
	;

init_declarator:
	declarator asm_phrase_opt attribute_opt initializer_opt
		{ $$ = $4 ? $4 : $3 ? $3 : $2 ? $2 : $1; }
	;

/* Hang on to the specifiers so that we can reuse them.  */
decl_specifier_seq_opt:
	/* empty */				{ decl_spec = NULL; }
	| decl_specifier_seq
	;

decl_specifier_seq:
	attribute_opt decl_specifier		{ decl_spec = *$2; }
	| decl_specifier_seq decl_specifier	{ decl_spec = *$2; }
	| decl_specifier_seq ATTRIBUTE_PHRASE	{ decl_spec = *$2; }
	;

decl_specifier:
	storage_class_specifier
		{ /* Version 2 checksumming ignores storage class, as that
		     is really irrelevant to the linkage.  */
		  remove_node($1);
		  $$ = $1;
		}
	| type_specifier	{ dont_want_type_specifier = true; $$ = $1; }
	| type_qualifier
	;

storage_class_specifier:
	AUTO_KEYW
	| REGISTER_KEYW
	| STATIC_KEYW
	| EXTERN_KEYW	{ is_extern = 1; $$ = $1; }
	| INLINE_KEYW	{ is_extern = 0; $$ = $1; }
	;

type_specifier:
	simple_type_specifier
	| TYPEOF_KEYW '(' parameter_declaration ')'
	| TYPEOF_PHRASE

	/* References to s/u/e's defined elsewhere.  Rearrange things
	   so that it is easier to expand the definition fully later.  */
	| STRUCT_KEYW attribute_opt IDENT
		{ remove_node($1); (*$3)->tag = SYM_STRUCT; $$ = $3; }
	| UNION_KEYW attribute_opt IDENT
		{ remove_node($1); (*$3)->tag = SYM_UNION; $$ = $3; }
	| ENUM_KEYW IDENT
		{ remove_node($1); (*$2)->tag = SYM_ENUM; $$ = $2; }

	/* Full definitions of an s/u/e.  Record it.  */
	| STRUCT_KEYW attribute_opt IDENT class_body
		{ record_compound($1, $3, $4, SYM_STRUCT); $$ = $4; }
	| UNION_KEYW attribute_opt IDENT class_body
		{ record_compound($1, $3, $4, SYM_UNION); $$ = $4; }
	| ENUM_KEYW IDENT enum_body
		{ record_compound($1, $2, $3, SYM_ENUM); $$ = $3; }
	/*
	 * Anonymous enum definition. Tell add_symbol() to restart its counter.
	 */
	| ENUM_KEYW enum_body
		{ add_symbol(NULL, SYM_ENUM, NULL, 0); $$ = $2; }
	/* Anonymous s/u definitions.  Nothing needs doing.  */
	| STRUCT_KEYW attribute_opt class_body		{ $$ = $3; }
	| UNION_KEYW attribute_opt class_body		{ $$ = $3; }
	;

simple_type_specifier:
	CHAR_KEYW
	| SHORT_KEYW
	| INT_KEYW
	| LONG_KEYW
	| SIGNED_KEYW
	| UNSIGNED_KEYW
	| FLOAT_KEYW
	| DOUBLE_KEYW
	| VOID_KEYW
	| BOOL_KEYW
	| VA_LIST_KEYW
	| BUILTIN_INT_KEYW
	| TYPE			{ (*$1)->tag = SYM_TYPEDEF; $$ = $1; }
	;

ptr_operator:
	'*' type_qualifier_seq_opt
		{ $$ = $2 ? $2 : $1; }
	;

type_qualifier_seq_opt:
	/* empty */					{ $$ = NULL; }
	| type_qualifier_seq
	;

type_qualifier_seq:
	type_qualifier
	| ATTRIBUTE_PHRASE
	| type_qualifier_seq type_qualifier		{ $$ = $2; }
	| type_qualifier_seq ATTRIBUTE_PHRASE		{ $$ = $2; }
	;

type_qualifier:
	X86_SEG_KEYW
	| CONST_KEYW | VOLATILE_KEYW
	| RESTRICT_KEYW
		{ /* restrict has no effect in prototypes so ignore it */
		  remove_node($1);
		  $$ = $1;
		}
	;

declarator:
	ptr_operator declarator			{ $$ = $2; }
	| direct_declarator
	;

direct_declarator:
	IDENT
		{ if (current_name != NULL) {
		    error_with_pos("unexpected second declaration name");
		    YYERROR;
		  } else {
		    current_name = (*$1)->string;
		    $$ = $1;
		  }
		  dont_want_type_specifier = false;
		}
	| direct_declarator '(' parameter_declaration_clause ')'
		{ $$ = $4; }
	| direct_declarator '(' error ')'
		{ $$ = $4; }
	| direct_declarator BRACKET_PHRASE
		{ $$ = $2; }
	| '(' declarator ')'
		{ $$ = $3; }
	;

/* Nested declarators differ from regular declarators in that they do
   not record the symbols they find in the global symbol table.  */
nested_declarator:
	ptr_operator nested_declarator		{ $$ = $2; }
	| direct_nested_declarator
	;

direct_nested_declarator:
	direct_nested_declarator1
	| direct_nested_declarator1 '(' parameter_declaration_clause ')'
		{ $$ = $4; }
	;

direct_nested_declarator1:
	IDENT	{ $$ = $1; dont_want_type_specifier = false; }
	| direct_nested_declarator1 '(' error ')'
		{ $$ = $4; }
	| direct_nested_declarator1 BRACKET_PHRASE
		{ $$ = $2; }
	| '(' attribute_opt nested_declarator ')'
		{ $$ = $4; }
	| '(' error ')'
		{ $$ = $3; }
	;

parameter_declaration_clause:
	parameter_declaration_list_opt DOTS		{ $$ = $2; }
	| parameter_declaration_list_opt
	| parameter_declaration_list ',' DOTS		{ $$ = $3; }
	;

parameter_declaration_list_opt:
	/* empty */					{ $$ = NULL; }
	| parameter_declaration_list
	;

parameter_declaration_list:
	parameter_declaration
		{ $$ = $1; dont_want_type_specifier = false; }
	| parameter_declaration_list ',' parameter_declaration
		{ $$ = $3; dont_want_type_specifier = false; }
	;

parameter_declaration:
	decl_specifier_seq abstract_declarator_opt
		{ $$ = $2 ? $2 : $1; }
	;

abstract_declarator_opt:
	/* empty */				{ $$ = NULL; }
	| abstract_declarator
	;

abstract_declarator:
	ptr_operator
	| ptr_operator abstract_declarator
		{ $$ = $2 ? $2 : $1; }
	| direct_abstract_declarator attribute_opt
		{ $$ = $2; dont_want_type_specifier = false; }
	;

direct_abstract_declarator:
	direct_abstract_declarator1
	| direct_abstract_declarator1 open_paren parameter_declaration_clause ')'
		{ $$ = $4; }
	| open_paren parameter_declaration_clause ')'
		{ $$ = $3; }
	;

direct_abstract_declarator1:
	  IDENT
		{ /* For version 2 checksums, we don't want to remember
		     private parameter names.  */
		  remove_node($1);
		  $$ = $1;
		}
	| direct_abstract_declarator1 open_paren error ')'
		{ $$ = $4; }
	| direct_abstract_declarator1 BRACKET_PHRASE
		{ $$ = $2; }
	| open_paren attribute_opt abstract_declarator ')'
		{ $$ = $4; }
	| open_paren error ')'
		{ $$ = $3; }
	| BRACKET_PHRASE
	;

open_paren:
	'('	{ $$ = $1; dont_want_type_specifier = false; }
	;

function_definition:
	decl_specifier_seq_opt declarator BRACE_PHRASE
		{ struct string_list *decl = *$2;
		  *$2 = NULL;
		  add_symbol(current_name, SYM_NORMAL, decl, is_extern);
		  $$ = $3;
		}
	;

initializer_opt:
	/* empty */					{ $$ = NULL; }
	| initializer
	;

/* We never care about the contents of an initializer.  */
initializer:
	'=' EXPRESSION_PHRASE
		{ remove_list($2, &(*$1)->next); $$ = $2; }
	;

class_body:
	'{' member_specification_opt '}'		{ $$ = $3; }
	| '{' error '}'					{ $$ = $3; }
	;

member_specification_opt:
	/* empty */					{ $$ = NULL; }
	| member_specification
	;

member_specification:
	member_declaration
	| member_specification member_declaration	{ $$ = $2; }
	;

member_declaration:
	decl_specifier_seq_opt member_declarator_list_opt ';'
		{ $$ = $3; dont_want_type_specifier = false; }
	| error ';'
		{ $$ = $2; dont_want_type_specifier = false; }
	;

member_declarator_list_opt:
	/* empty */					{ $$ = NULL; }
	| member_declarator_list
	;

member_declarator_list:
	member_declarator
		{ $$ = $1; dont_want_type_specifier = true; }
	| member_declarator_list ',' member_declarator
		{ $$ = $3; dont_want_type_specifier = true; }
	;

member_declarator:
	nested_declarator attribute_opt			{ $$ = $2 ? $2 : $1; }
	| IDENT member_bitfield_declarator		{ $$ = $2; }
	| member_bitfield_declarator
	;

member_bitfield_declarator:
	':' EXPRESSION_PHRASE				{ $$ = $2; }
	;

attribute_opt:
	/* empty */					{ $$ = NULL; }
	| attribute_opt ATTRIBUTE_PHRASE		{ $$ = $2; }
	;

enum_body:
	'{' enumerator_list '}'				{ $$ = $3; }
	| '{' enumerator_list ',' '}'			{ $$ = $4; }
	 ;

enumerator_list:
	enumerator
	| enumerator_list ',' enumerator

enumerator:
	IDENT
		{
			const char *name = (*$1)->string;
			add_symbol(name, SYM_ENUM_CONST, NULL, 0);
		}
	| IDENT '=' EXPRESSION_PHRASE
		{
			const char *name = (*$1)->string;
			struct string_list *expr = copy_list_range(*$3, *$2);
			add_symbol(name, SYM_ENUM_CONST, expr, 0);
		}

asm_definition:
	ASM_PHRASE ';'					{ $$ = $2; }
	;

asm_phrase_opt:
	/* empty */					{ $$ = NULL; }
	| ASM_PHRASE
	;

export_definition:
	EXPORT_SYMBOL_KEYW '(' IDENT ')' ';'
		{ export_symbol((*$3)->string); $$ = $5; }
	;

/* Ignore any module scoped _Static_assert(...) */
static_assert:
	STATIC_ASSERT_PHRASE ';'			{ $$ = $2; }
	;

%%

static void
yyerror(const char *e)
{
  error_with_pos("%s", e);
}
