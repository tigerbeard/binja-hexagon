/*
 *  Copyright(c) 2019-2020 Qualcomm Innovation Center, Inc. All Rights Reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This program generates the semantics file that is processed by
 * the do_qemu.py script.  We use the C preporcessor to manipulate the
 * files imported from the Hexagon architecture library.
 */

#include <stdio.h>
#include <string.h>
#define STRINGIZE(X) #X

/*
 * QEMU's legacy encodings (LEGACY_DEF_ENC32) are older encodings of current
 * instructions, which the PRM lists as Rd=add(Rs,Rt):sat:deprecated and so on.
 * Each one becomes an instruction of its own, TAG_deprecated, with TAG's
 * semantics and attributes and ":deprecated" after its syntax.
 */
typedef struct {
  const char *tag;
  const char *beh;
  const char *sem;
  const char *attribs;
} InsnText;

static const InsnText insn_texts[] = {
#define Q6INSN(TAG, BEH, ATTRIBS, DESCR, SEM)                                  \
  {#TAG, STRINGIZE(BEH), STRINGIZE(SEM), STRINGIZE(ATTRIBS)},
#define EXTINSN(TAG, BEH, ATTRIBS, DESCR, SEM)                                 \
  Q6INSN(TAG, BEH, ATTRIBS, DESCR, SEM)
#include "third_party/qemu-hexagon/imported/allidefs.def"
#undef Q6INSN
#undef EXTINSN
};

static int print_legacy_insn(FILE *outfile, const char *tag) {
  size_t i;
  for (i = 0; i < sizeof(insn_texts) / sizeof(insn_texts[0]); i++) {
    const InsnText *insn = &insn_texts[i];
    if (strcmp(insn->tag, tag) == 0) {
      fprintf(outfile,
              "SEMANTICS( \\\n"
              "    \"%s_deprecated\", \\\n"
              "    %s \":deprecated\", \\\n"
              "    \"\"\"%s\"\"\" \\\n"
              ")\n",
              tag, insn->beh, insn->sem);
      fprintf(outfile,
              "ATTRIBUTES( \\\n"
              "    \"%s_deprecated\", \\\n"
              "    \"%s\" \\\n"
              ")\n",
              tag, insn->attribs);
      return 0;
    }
  }
  fprintf(stderr, "No instruction %s for its legacy encoding\n", tag);
  return 1;
}

int main(int argc, char *argv[]) {
  FILE *outfile;

  if (argc != 2) {
    fprintf(stderr, "Usage: gen_semantics ouptputfile\n");
    return 1;
  }
  outfile = fopen(argv[1], "w");
  if (outfile == NULL) {
    fprintf(stderr, "Cannot open %s for writing\n", argv[1]);
    return 1;
  }

/*
 * Process the instruction definitions
 *     Scalar core instructions have the following form
 *         Q6INSN(A2_add,"Rd32=add(Rs32,Rt32)",ATTRIBS(),
 *         "Add 32-bit registers",
 *         { RdV=RsV+RtV;})
 *     HVX instructions have the following form
 *         EXTINSN(V6_vinsertwr, "Vx32.w=vinsert(Rt32)",
 *         ATTRIBS(A_EXTENSION,A_CVI,A_CVI_VX),
 *         "Insert Word Scalar into Vector",
 *         VxV.uw[0] = RtV;)
 */
#define Q6INSN(TAG, BEH, ATTRIBS, DESCR, SEM)                                  \
  do {                                                                         \
    fprintf(outfile,                                                           \
            "SEMANTICS( \\\n"                                                  \
            "    \"%s\", \\\n"                                                 \
            "    %s, \\\n"                                                     \
            "    \"\"\"%s\"\"\" \\\n"                                          \
            ")\n",                                                             \
            #TAG, STRINGIZE(BEH), STRINGIZE(SEM));                             \
    fprintf(outfile,                                                           \
            "ATTRIBUTES( \\\n"                                                 \
            "    \"%s\", \\\n"                                                 \
            "    \"%s\" \\\n"                                                  \
            ")\n",                                                             \
            #TAG, STRINGIZE(ATTRIBS));                                         \
  } while (0);
#define EXTINSN(TAG, BEH, ATTRIBS, DESCR, SEM)                                 \
  do {                                                                         \
    fprintf(outfile,                                                           \
            "SEMANTICS( \\\n"                                                  \
            "    \"%s\", \\\n"                                                 \
            "    %s, \\\n"                                                     \
            "    \"\"\"%s\"\"\" \\\n"                                          \
            ")\n",                                                             \
            #TAG, STRINGIZE(BEH), STRINGIZE(SEM));                             \
    fprintf(outfile,                                                           \
            "ATTRIBUTES( \\\n"                                                 \
            "    \"%s\", \\\n"                                                 \
            "    \"%s\" \\\n"                                                  \
            ")\n",                                                             \
            #TAG, STRINGIZE(ATTRIBS));                                         \
  } while (0);
#include "third_party/qemu-hexagon/imported/allidefs.def"
#undef Q6INSN
#undef EXTINSN

  {
    int errors = 0;
#define LEGACY_DEF_ENC32(TAG, ENCSTR) errors += print_legacy_insn(outfile, #TAG);
#include "third_party/qemu-hexagon/imported/encode.def"
#undef LEGACY_DEF_ENC32
    if (errors) {
      return 1;
    }
  }

/*
 * Process the macro definitions
 *     Macros definitions have the following form
 *         DEF_MACRO(
 *             fLSBNEW0,
 *             predlog_read(thread,0),
 *             ()
 *         )
 * The important part here is the attributes.  Whenever an instruction
 * invokes a macro, we add the macro's attributes to the instruction.
 */
#define DEF_MACRO(MNAME, BEH, ATTRS)                                           \
  fprintf(outfile,                                                             \
          "MACROATTRIB( \\\n"                                                  \
          "    \"%s\", \\\n"                                                   \
          "    \"\"\"%s\"\"\", \\\n"                                           \
          "    \"%s\" \\\n"                                                    \
          ")\n",                                                               \
          #MNAME, STRINGIZE(BEH), STRINGIZE(ATTRS));
#include "third_party/qemu-hexagon/imported/macros.def"
#undef DEF_MACRO

/*
 * Process the macros for HVX
 */
#define DEF_MACRO(MNAME, BEH, ATTRS)                                           \
  fprintf(outfile,                                                             \
          "MACROATTRIB( \\\n"                                                  \
          "    \"%s\", \\\n"                                                   \
          "    \"\"\"%s\"\"\", \\\n"                                           \
          "    \"%s\" \\\n"                                                    \
          ")\n",                                                               \
          #MNAME, STRINGIZE(BEH), STRINGIZE(ATTRS));
#include "third_party/qemu-hexagon/imported/allext_macros.def"
#undef DEF_MACRO

  fclose(outfile);
  return 0;
}
