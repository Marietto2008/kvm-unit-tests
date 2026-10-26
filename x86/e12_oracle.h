/*
 * Oracolo PURO di ept12_remap_sentinel (parere #75 §5). Nessuna dipendenza dal
 * framework kvm-unit-tests: lo include vmx_tests.c e lo collauda sull'host
 * freebsd-nested/tools/nested/e12_oracle_test.c, che simula anche il vecchio
 * difetto (RIP non avanzato dopo il VMCALL di stage0) e pretende un FAIL.
 */
#ifndef E12_ORACLE_H
#define E12_ORACLE_H

#define E12_GUARD	0xdeadbeefu	/* messo da L1 a stage0, mai scritto da L2 */
#define E12_S1_MARK	0x5e171e11u	/* scritto SOLO dal codice L2 di stage1 */

enum e12_verdict {
	E12_PASS = 0,
	E12_F_NOSKIP,		/* il VMCALL di stage0 non e' stato saltato (len 3) */
	E12_F_RIP_SAME,		/* VMCALL di stage1 = VMCALL di stage0: stage1 non eseguita */
	E12_F_RIP_WRONG,	/* VMCALL di stage1 non all'indirizzo atteso */
	E12_F_NOMARK,		/* marcatore di L2 assente */
	E12_F_NOREAD,		/* valore letto = guardia: la mov non ha scritto */
	E12_F_STALE,		/* valore = pagina vecchia */
	E12_F_VALUE,		/* valore inatteso */
};

/*
 * PASS solo se TUTTO e' stato osservato: skip di stage0, VMCALL di stage1
 * distinto da quello di stage0 E all'indirizzo dell'etichetta, marcatore
 * scritto da L2, dato della pagina nuova. Ogni altra combinazione e' FAIL.
 */
static inline enum e12_verdict
e12_sentinel_verdict(int skip0_ok, unsigned long long rip0,
    unsigned long long rip1, unsigned long long vmcall_addr,
    unsigned int marker, unsigned int seen,
    unsigned int magic_old, unsigned int magic_new)
{
	if (!skip0_ok)
		return (E12_F_NOSKIP);
	if (rip1 == rip0)
		return (E12_F_RIP_SAME);
	if (rip1 != vmcall_addr)
		return (E12_F_RIP_WRONG);
	if (marker != E12_S1_MARK)
		return (E12_F_NOMARK);
	if (seen == E12_GUARD)
		return (E12_F_NOREAD);
	if (seen == magic_old)
		return (E12_F_STALE);
	if (seen != magic_new)
		return (E12_F_VALUE);
	return (E12_PASS);
}

static inline const char *
e12_verdict_str(enum e12_verdict v)
{
	switch (v) {
	case E12_PASS:		return ("PASS");
	case E12_F_NOSKIP:	return ("FAIL: VMCALL di stage0 non saltato");
	case E12_F_RIP_SAME:	return ("FAIL: VMCALL di stage1 = stage0, stage1 NON eseguita");
	case E12_F_RIP_WRONG:	return ("FAIL: VMCALL di stage1 a un indirizzo inatteso");
	case E12_F_NOMARK:	return ("FAIL: marcatore di stage1 non scritto da L2");
	case E12_F_NOREAD:	return ("FAIL: valore = guardia, la lettura non ha scritto");
	case E12_F_STALE:	return ("FAIL: stantio (pagina vecchia)");
	case E12_F_VALUE:	return ("FAIL: valore inatteso");
	}
	return ("FAIL: esito sconosciuto");
}

/*
 * Parere #76, ept12_remap ordinario, stage 2: la scrittura sulla sonda con
 * EPT12 R-X deve arrivare a L1 come EPT violation di SCRITTURA (bit 1), dalla
 * istruzione di scrittura (write_addr), sulla pagina della sonda, con i
 * permessi EPT12 riportati nei bit 5:3 = R-X (0b101). Ritorna 1 solo se tutto.
 */
static inline int
e12_s2_fault_check(unsigned long long gpa, unsigned long long probe,
    unsigned long long rip, unsigned long long write_addr,
    unsigned long long qual)
{
	return ((gpa & ~0xfffull) == (probe & ~0xfffull) &&
	    rip == write_addr &&
	    (qual & 0x2) != 0 &&
	    ((qual >> 3) & 0x7) == 0x5);
}

enum e12_s3_verdict {
	E12_S3_PASS = 0,
	E12_S3_F_NOFAULT,	/* la scrittura non ha fatto la violation attesa */
	E12_S3_F_RIP,		/* VMCALL di stage3 non all'indirizzo atteso */
	E12_S3_F_VALUE,		/* la pagina non contiene il valore scritto */
};

/* Stage 3: PASS solo con violation di stage 2 verificata, VMCALL finale
 * all'indirizzo atteso e il valore scritto da L2 visibile nella pagina. */
static inline enum e12_s3_verdict
e12_s3_verdict(int s2_fault_ok, unsigned long long rip3,
    unsigned long long vmcall_addr, unsigned int page_val, unsigned int magic3)
{
	if (!s2_fault_ok)
		return (E12_S3_F_NOFAULT);
	if (rip3 != vmcall_addr)
		return (E12_S3_F_RIP);
	if (page_val != magic3)
		return (E12_S3_F_VALUE);
	return (E12_S3_PASS);
}

static inline const char *
e12_s3_str(enum e12_s3_verdict v)
{
	switch (v) {
	case E12_S3_PASS:	return ("PASS");
	case E12_S3_F_NOFAULT:	return ("FAIL: la scrittura di stage2 non ha fatto la violation attesa");
	case E12_S3_F_RIP:	return ("FAIL: VMCALL di stage3 a un indirizzo inatteso");
	case E12_S3_F_VALUE:	return ("FAIL: la pagina non contiene il valore scritto da L2");
	}
	return ("FAIL: esito sconosciuto");
}

#endif
