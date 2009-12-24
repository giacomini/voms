%{
/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include "listfunc.h"

#include "parsertypes.h"

char **nmlistadd(char **vect, char *data, int size);
char **parse_subjects(char *string);
void namespaceserror(void *policies, void *scanner, char const *msg);
%}

%error-verbose
%pure-parser
%name-prefix="namespaces"
%parse-param {struct policy ***policies}
%parse-param {void *scanner}
%lex-param   {void *scanner}

%union{
  char *string;
  struct condition *cond;
  struct policy *policy;
  int integer;
}

%token <string> SUBJECT
%token TO
%token SELF
%token PERMIT
%token DENY
%token SUBJECT_WORD
%token ISSUER

%type <policy>  rule
%type <cond>    condition
%type <integer> permit_or_deny

%%

eacl: rule  { *policies = nmlistadd(*policies, $1, sizeof($1)); }
| eacl rule { *policies = nmlistadd(*policies, $2, sizeof($2)); }
;

rule: TO ISSUER SUBJECT condition {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));
  if ($$) {
    $$->self = 0;
    $$->caname = strdup($3);
    $$->conds = nmlistadd(NULL, $4, sizeof(struct condition *));
    $$->type = TYPE_NAMESPACE;
  }

 }
| TO ISSUER SELF condition {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));
  if ($$) {
    $$->self = 1;
    $$->caname = NULL;
    $$->conds = nmlistadd(NULL, $4, sizeof(struct condition *));
    $$->type = TYPE_NAMESPACE;
  }
 }
;

condition: permit_or_deny SUBJECT_WORD SUBJECT {
  $$ = (struct condition *)calloc(1, sizeof(struct condition));
  if ($$) {
    $$->positive = $1;
    $$->original = strdup($3);
    $$->subjects = nmlistadd(NULL, $$->original, sizeof(char*));
    if (!$$->subjects) {
      free($$->original);
      free($$);
        $$ = NULL;
    }
  }
}
;

permit_or_deny: PERMIT { $$ = 1; }
| DENY { $$ = 0; }
;

%%

char **nmlistadd(char **vect, char *data, int size)
{
  int i = 0;
  char **newvect;

  if (!data || (size <= 0))
    return NULL;

  if (vect)
    while (vect[i++]) ;
  else
    i=1;

  if ((newvect = (char **)malloc((i+1)*size))) {
    if (vect) {
      memcpy(newvect, vect, (size*(i-1)));
      newvect[i-1] = data;
      newvect[i] = NULL;
      free(vect);
    }
    else {
      newvect[0] = data;
      newvect[1] = NULL;
    }
    return newvect;
  }
  return NULL;
}

#if 0
int main()
{
  namespacesdebug = 1;
  void **arg = NULL;
  void *scanner=NULL;
  namespaceslex_init(&scanner);
  namespacesset_debug(1, scanner);
  return namespacesparse(arg, scanner);
}
#endif

void namespaceserror(void *policies, void *scanner, char const *msg)
{
}