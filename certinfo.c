#include <stdio.h>
#include <unistd.h>
#include <matrixssl/matrixInternal.h>
#include "strbuf.h"

#define KU_DIGITAL_SIGNATURE    0x0080
#define KU_NON_REPUDIATION      0x0040
#define KU_KEY_ENCIPHERMENT     0x0020
#define KU_DATA_ENCIPHERMENT    0x0010
#define KU_KEY_AGREEMENT        0x0008
#define KU_KEY_CERT_SIGN        0x0004
#define KU_CRL_SIGN             0x0002
#define KU_ENCIPHER_ONLY        0x0001
#define KU_DECIPHER_ONLY        0x8000

#define SHOW_ISSUER  1
#define SHOW_SUBJECT 2
#define SHOW_OTHER   4

#define OPT_CN               (1<<0)
#define OPT_COUNTRY	      (1<<1)
#define OPT_LOCALITY	      (1<<2)
#define OPT_ORGANIZATION      (1<<3)
#define OPT_ORGUNIT	      (1<<4)

#define ISSUER_CN            (1<<0)
#define ISSUER_COUNTRY        (1<<1)
#define ISSUER_LOCALITY       (1<<2)
#define ISSUER_ORGANIZATION   (1<<3)
#define ISSUER_ORGUNIT	      (1<<4)
#define ISSUER_EMAIL  	      (1<<5)

#define SUBJECT_SHIFT	      8
#define SUBJECT_CN            (1<<(0 + SUBJECT_SHIFT))
#define SUBJECT_COUNTRY       (1<<(1 + SUBJECT_SHIFT))
#define SUBJECT_LOCALITY      (1<<(2 + SUBJECT_SHIFT))
#define SUBJECT_ORGANIZATION  (1<<(3 + SUBJECT_SHIFT))
#define SUBJECT_ORGUNIT	      (1<<(4 + SUBJECT_SHIFT))
#define SUBJECT_EMAIL	      (1<<(5 + SUBJECT_SHIFT))

#define ISSUER_ALL  \
  ISSUER_CN|ISSUER_COUNTRY|ISSUER_LOCALITY|ISSUER_ORGANIZATION|ISSUER_ORGUNIT
#define SUBJECT_ALL \
  SUBJECT_CN|SUBJECT_COUNTRY|SUBJECT_LOCALITY|SUBJECT_ORGANIZATION|SUBJECT_ORGUNIT

#define PRETTYFMT  "  %s = %s\n"
#define SHELLFMT   "%s=\"%s\"\n"

static const char months[12][4] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

char *issuerinfo = NULL;
char *subjectinfo = NULL;
char *outfmt = PRETTYFMT;
int what = 0;
int prettyprint = 1;

strbuf_t outbuf = STRBUF_ZERO;

static int writeif(char *prefix, char *name, char *value, char *info)
{
  if (value) {
    if (!info) {
      if (prettyprint)
	strbuf_appendf(&outbuf, "  %s = %s\n", name, value);
      else
	strbuf_appendf(&outbuf, "%s%s=\"%s\"\n", prefix, name, value);
    } else if (!strcmp(name, info))
      strbuf_appendf(&outbuf, "%s\n", value);
    return 0;
  }
  return 1;
}

char *algoName(int id)
{
  switch (id) {
  case 645:
    return "rsaEncryption";
  case 646:
    return "md2WithRSAEncryption";
  case 648:
    return "md5WithRSAEncryption";
  case 649:
    return "sha1WithRSAEncryption";
  default:
    return "unknown encryption";
  }
}

void keyusage(int id)
{
  /* "X509v3 Key Usage:" */
  if (!id)
    return;

  strbuf_appendf(&outbuf, "X509v3 Key Usage:      ");

  if (id & KU_DIGITAL_SIGNATURE)
    strbuf_appends(&outbuf, "Digital Signature, ");
  if (id & KU_NON_REPUDIATION)
    strbuf_appends(&outbuf, "Non Repudiation, ");
  if (id & KU_KEY_ENCIPHERMENT)
    strbuf_appends(&outbuf, "Key Encipherment, ");
  if (id & KU_DATA_ENCIPHERMENT)
    strbuf_appends(&outbuf, "Data Encipherment, ");
  if (id & KU_KEY_AGREEMENT)
    strbuf_appends(&outbuf, "Key Agreement, ");
  if (id & KU_KEY_CERT_SIGN)
    strbuf_appends(&outbuf, "Certificate Sign, ");
  if (id & KU_CRL_SIGN)
    strbuf_appends(&outbuf, "CRL Sign, ");
  if (id & KU_ENCIPHER_ONLY)
    strbuf_appends(&outbuf, "Encipher Only, ");
  if (id & KU_DECIPHER_ONLY)
    strbuf_appends(&outbuf, "Decipher Only, ");
  strbuf_setlength(&outbuf, outbuf.len - 2);
  strbuf_appends(&outbuf, "\n");
}

#define TOINT(i) (src[i]-'0')
/**
 * !!!WARNING!!! this isn't a generic algo
 * we assume here libmatrixssl will give us a valid time string
 */
void print_formated_date(char *src)
{
  int tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec;
  char *tz = "";
  char tm[] = " 0 00:00:00";

  if (strlen(src) > 13) {
    /* rfc2459
     * 4.1.2.5.2  GeneralizedTime
     */
    tm_year = TOINT(0) * 1000 + TOINT(1) * 100 + TOINT(2) * 10 + TOINT(3);
    src += 2;
  } else {
    tm_year = TOINT(0) * 10 + TOINT(1);
    /* rfc2459
     * 4.1.2.5.1  UTCTime
     *
     * Where YY is greater than or equal to 50, the year shall be
     * interpreted as 19YY; and
     * 
     * Where YY is less than 50, the year shall be interpreted as 20YY.
     */
    tm_year = (tm_year < 50) ? tm_year + 2000 : tm_year + 1900;
  }
  tm_mon = TOINT(2) * 10 + TOINT(3) - 1;
  tm_mday = TOINT(4) * 10 + TOINT(5);
  tm_hour = TOINT(6) * 10 + TOINT(7);
  tm_min = TOINT(8) * 10 + TOINT(9);
  tm_sec = TOINT(10) * 10 + TOINT(11);

  if (src[12] == 'Z' || src[12] == 'z')
    tz = " GMT";


  tm[0] = (tm_mday < 10) ? ' ' : tm_mday / 10 + '0';
  tm[1] = tm_mday % 10 + '0';

  tm[3] = tm_hour / 10 + '0';
  tm[4] = tm_hour % 10 + '0';

  tm[6] = tm_min / 10 + '0';
  tm[7] = tm_min % 10 + '0';

  tm[9] = tm_sec / 10 + '0';
  tm[10] = tm_sec % 10 + '0';

  strbuf_appendf(&outbuf, "%s %s %d%s\n", months[tm_mon], tm, tm_year, tz);
}

void printGeneralizedTime(char *key, char *src)
{
  char *pre = "";
  if (strlen(src) == 13) {	/* "YYMMDDHHMMSSZ" */
    if ((TOINT(0) * 10 + TOINT(1)) < 50)
      pre = "20";
    else
      pre = "50";
  }
  strbuf_appendf(&outbuf, "%s=\"%s%s\"\n", key, pre, src);
}

void printHexBuf(unsigned char *buf, int len)
{
  int i = 0;
  const char digits[16] = "0123456789abcdef";
  strbuf_appends(&outbuf, "  ");
  for (;;) {
    char hex[2];
    hex[0] = digits[(buf[i] >> 4) & 0xf];
    hex[1] = digits[buf[i] & 0xf];
    strbuf_nappends(&outbuf, hex, 2);
    if (i++ > len - 2)
      break;
    strbuf_appends(&outbuf, ":");
    if (!(i % 20))
      strbuf_appends(&outbuf, "\n  ");
  }
  strbuf_appends(&outbuf, "\n");
}

void show_other_info(sslRsaCert_t * Cert, char *info)
{
  if (prettyprint) {
    strbuf_appendf(&outbuf, "Version:               %d\n", Cert->version + 1);
    strbuf_appends(&outbuf, "Validity:\n");
    strbuf_appends(&outbuf, "  Not valid before:      ");
    print_formated_date(Cert->notBefore);
    strbuf_appends(&outbuf, "  Not valid after:       ");
    print_formated_date(Cert->notAfter);
    strbuf_appendf(&outbuf, "Certificate algorithm: %s\n",
		   algoName(Cert->certAlgorithm));
    strbuf_appendf(&outbuf, "Public key algorithm:  %s\n",
		   algoName(Cert->pubKeyAlgorithm));
    strbuf_appendf(&outbuf, "Serial number:         %d\n",
		   (int) *Cert->serialNumber);
    keyusage(Cert->extensions.keyUsage);
    strbuf_appendf(&outbuf, "Signature Length       %d\n", Cert->signatureLen);
    strbuf_appendf(&outbuf, "Signature algorithm:   %s\n",
		   algoName(Cert->sigAlgorithm));
    printHexBuf(Cert->signature, Cert->signatureLen);
  } else {
    strbuf_appendf(&outbuf, "VERSION=\"%d\"\n", Cert->version + 1);
    strbuf_appendf(&outbuf, "SERIAL=\"%d\"\n", (int) *Cert->serialNumber);
    printGeneralizedTime("NOTBEFORE", Cert->notBefore);
    printGeneralizedTime("NOTAFTER", Cert->notAfter);
  }
}

static void show_common_info(DNattributes_t * dn, char *prefix, char *info)
{
  writeif(prefix, "C", dn->country, info);
  writeif(prefix, "L", dn->locality, info);
  writeif(prefix, "O", dn->organization, info);
  writeif(prefix, "OU", dn->orgUnit, info);
  if (dn->commonNameList) {
    int x = 0;
    while (dn->commonNameList[x])
      writeif(prefix, "CN", dn->commonNameList[x++], info);
  }
}

void show_issuer_info(sslRsaCert_t * Cert, char *info)
{
  if (!info && prettyprint)
    strbuf_appends(&outbuf, "Issuer:\n");
  show_common_info(&Cert->issuer, "i", info);
  writeif("i", "EMAIL", (char *) Cert->extensions.ian.email, info);
}

void show_subject_info(sslRsaCert_t * Cert, char *info)
{
  if (!info && prettyprint)
    strbuf_appends(&outbuf, "Subject:\n");
  show_common_info(&Cert->subject, "s", info);
  writeif("s", "EMAIL", (char *) Cert->extensions.san.email, info);
}

static void __attribute__ ((noreturn)) usage()
{
  strbuf_puts(&outbuf,
	      "certinfo (" VERSION ")\n"
	      "usage: certinfo [ options ] file\n"
	      "  -a ....... show full info\n"
	      "  -e ....... sh_e_ll parseable output\n"
	      "  -i ....... show only issuer info\n"
	      "  -s ....... show only subject info\n"
	      "  -I attr .. show only attrib 'attr' from issuer\n"
	      "  -S attr .. show only attrib 'attr' from subject\n"
	      "     valid attributes are: C, L, O, OU, CN, EMAIL\n");
  write(2, outbuf.s, outbuf.len);
  _exit(0);
}

int main(int argc, char **argv)
{
  int caCertLen, retval;
  unsigned char *caCert;
  char *caFile;
  sslRsaCert_t *currCert = NULL;
#ifdef HAS_SSLCHAINLEN_T
  sslChainLen_t chain;
#endif

  while ((retval = getopt(argc, argv, "aeiI:sS:")) != -1) {
    switch (retval) {
    case 'e':
      outfmt = SHELLFMT;
      prettyprint = 0;
      break;
    case 'a':
      what |= (SHOW_ISSUER | SHOW_SUBJECT | SHOW_OTHER);
      break;
    case 'I':
      if (issuerinfo)
	usage();
      else
	issuerinfo = optarg;
      what |= SHOW_ISSUER;
      break;
    case 'i':
      what |= SHOW_ISSUER;
      break;
    case 'S':
      if (subjectinfo)
	usage();
      else
	subjectinfo = optarg;
      what |= SHOW_SUBJECT;
      break;
    case 's':
      what |= SHOW_SUBJECT;
      break;
    default:
      usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (!argc)
    usage();

  caFile = *argv++;

#ifdef HAS_SSLCHAINLEN_T
  if ((retval =
       matrixX509ReadCert(NULL, caFile, &caCert, &caCertLen, &chain)) < 0
#else
  if ((retval = matrixX509ReadCert(NULL, caFile, &caCert, &caCertLen)) < 0
#endif
      || caCert == NULL) {
    strbuf_putf(&outbuf, "Error reading cert file %s: %d\n", caFile, retval);
    write(2, outbuf.s, outbuf.len);
    exit(1);
  }

  if ((retval = matrixX509ParseCert(NULL, caCert, caCertLen, &currCert)) < 0) {
    psFree(caCert);
    strbuf_putf(&outbuf, "Error parsing cert %s: %d\n", caFile, retval);
    write(2, outbuf.s, outbuf.len);
    exit(1);
  }

  if (what & SHOW_OTHER)
    show_other_info(currCert, issuerinfo);
  if (what & SHOW_ISSUER)
    show_issuer_info(currCert, issuerinfo);
  if (what & SHOW_SUBJECT)
    show_subject_info(currCert, subjectinfo);
  write(1, outbuf.s, outbuf.len);
  exit(0);
}
