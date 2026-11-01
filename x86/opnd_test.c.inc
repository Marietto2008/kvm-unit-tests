/*
 * opnd_test.c.inc (v2) -- Claude 31/10/2026, pareri #160-#167R1 (sezione B del dossier di protocollo): collaudo
 * d'INTEGRAZIONE dello stadio 9 (R6/R3/R7/m128/R8/EPTP/W4G/EA). L1 = questo KUT, gia' in VMX operation (test v2) con
 * un VMCS corrente; ogni caso e' UNA istruzione VMX con operando in memoria. P0/P1 sono due pagine virtuali
 * consecutive (OPND_VA, OPND_VA + 4K) su due pagine fisiche NON adiacenti (verificato nei due versi, o il test si
 * ferma); sentinelle sull'intera pagina, scritte e lette tramite l'alias d'identita' (mai tramite OPND_VA).
 *
 * Fasi (piano dalla COM1: "F1,F2,F3" o un sottoinsieme in quest'ordine, oppure "F4" da sola):
 *   F1 operandi validi a cavallo di pagina (+ INVEPT con EPTP non valido: VMfail 28), e i controlli a 0x100
 *   F2 #PF autentici sulla seconda pagina (non presente; sola lettura per le scritture)
 *   F3 R8: CPL 3 -> #GP(0) (L1 gia' in VMX operation virtuale)
 *   F4 TERMINALE: la seconda pagina su un GPA senza memoria -> l'host chiude il latch e VM_RUN = 95: questo KUT NON
 *      deve tornare dall'istruzione. Se torna, lo scrive.
 * Contabilita' (#167R1 §6): "OPND ATTESI casi=N controlli=M" dopo il piano; ogni caso una riga "OPND CASO", ogni
 * controllo aggiuntivo una riga "OPND CONTROLLO", ogni prerequisito fallito una riga "OPND PREREQ"; OGNI errore ha
 * la sua riga "-> ERRATO". Chiusura: "OPND FINE casi=N controlli=M errati=E".
 * Copertura dichiarata: "nessuna invalidazione" con EPTP non valido e' un ATTESO (si controllano esito e memoria, non
 * la permanenza di una traduzione).
 */
#define OPND_VA		0x600000000000ULL
#define OPND_COM1	0x3f8
#define OPND_ATTESA	(30ULL * 1000 * 1000 * 1000)	/* cicli di TSC per il piano */
#define OPND_F		(X86_EFLAGS_CF | X86_EFLAGS_ZF)
#define OPND_RIP_SENT	0xfeedface00001234ULL		/* GUEST_RIP di partenza del VMCS di lavoro */
#define OPND_NESSUNO	0xffffffffffffffffULL		/* VMPTRST senza VMCS corrente */

static u8 *opnd_a0, *opnd_a1;			/* alias d'identita' di P0 e P1 */
static pteval_t *opnd_pte1;
static pteval_t opnd_pte1_ok;
static struct vmcs *opnd_cur, *opnd_tmp;
static bool opnd_tmp_usato;
static int opnd_n, opnd_nc, opnd_err;
static u64 opnd_ctls2;
static u8 opnd_im0[PAGE_SIZE], opnd_im1[PAGE_SIZE];

static int opnd_getc(void)
{
	u64 t0 = rdtsc();

	while (rdtsc() - t0 < OPND_ATTESA) {
		if (inb(OPND_COM1 + 5) & 1)
			return inb(OPND_COM1);
		pause();
	}
	return -1;
}

static bool opnd_fermo;			/* #169 R3: un prerequisito fallito ferma tutto quel che segue */

static void opnd_prereq(const char *cosa)
{
	opnd_err++;
	printf("OPND PREREQ %s -> ERRATO\n", cosa);
}

/* prerequisito fallito: riga, arresto, esito falso (nessuna operazione successiva sul VMCS) */
static bool opnd_ferma(const char *cosa)
{
	opnd_prereq(cosa);
	opnd_fermo = true;
	return (false);
}

/* #169 R3: ogni caricamento preparatorio ha il suo esito verificato */
static bool opnd_carica(struct vmcs *v, const char *cosa)
{
	if (make_vmcs_current(v))
		return (opnd_ferma(cosa));
	return (true);
}

static void opnd_controllo(const char *fase, const char *cosa, u64 osservato, u64 atteso)
{
	bool ok = osservato == atteso;

	opnd_nc++;
	if (!ok)
		opnd_err++;
	printf("OPND CONTROLLO %s %d %s: %#lx (atteso %#lx) -> %s\n", fase, opnd_nc, cosa, (unsigned long)osservato,
	    (unsigned long)atteso, ok ? "OK" : "ERRATO");
}

/*
 * Puntatore VMCS corrente GREZZO, letto con VMPTRST (parere Opus H2): la vmcs_save() upstream converte ~0 in NULL
 * (patch "Fix vmptrst result type", 2017) e virt_to_phys(NULL) = 0 non e' mai OPND_NESSUNO.
 */
static u64 opnd_corrente(void)
{
	u64 pa;

	asm volatile("vmptrst %0" : "=m"(pa) : : "memory", "cc");
	return (pa);
}

/*
 * Stato iniziale di OGNI caso (#167R1 §7): il VMCS di lavoro si CLEAR-a (verificato) prima di riusarne la memoria,
 * poi si inizializza (revisione), si carica, si scrive GUEST_RIP = sentinella e la si rilegge, lo si CLEAR-a di
 * nuovo e si rimette corrente il VMCS del framework; sentinelle sulle pagine; P1 presente e scrivibile.
 */
static bool opnd_stato(void)
{
	int i;

	/* #169 R3: al primo prerequisito fallito si FERMA: dopo un VMCLEAR fallito la regione (forse ancora attiva)
	 * non si tocca con accessi normali (SDM 3C 24.11.1), dopo un VMPTRLD fallito nessuna VMWRITE */
	if (opnd_fermo)
		return (false);
	if (opnd_tmp_usato && vmcs_clear(opnd_tmp))
		return (opnd_ferma("VMCLEAR del VMCS di lavoro prima del riuso"));
	memset(opnd_tmp, 0, PAGE_SIZE);
	opnd_tmp->hdr.revision_id = basic_msr.revision;
	opnd_tmp_usato = true;
	if (vmcs_clear(opnd_tmp))
		return (opnd_ferma("VMCLEAR del VMCS di lavoro nuovo"));
	if (!opnd_carica(opnd_tmp, "VMPTRLD del VMCS di lavoro"))
		return (false);
	if (vmcs_write(GUEST_RIP, OPND_RIP_SENT) || vmcs_read(GUEST_RIP) != OPND_RIP_SENT)
		return (opnd_ferma("GUEST_RIP sentinella nel VMCS di lavoro"));
	/* il VMCS di lavoro e' CORRENTE: dopo il suo VMCLEAR VMPTRST deve dare ~0 (verifica il mezzo d'osservazione) */
	if (vmcs_clear(opnd_tmp) || opnd_corrente() != OPND_NESSUNO)
		return (opnd_ferma("VMCLEAR del VMCS corrente: VMPTRST non da' 'nessun VMCS corrente'"));
	if (!opnd_carica(opnd_cur, "VMCS del framework di nuovo corrente"))
		return (false);
	if (opnd_corrente() != virt_to_phys(opnd_cur))
		return (opnd_ferma("VMCS del framework di nuovo corrente: VMPTRST diverso"));
	for (i = 0; i < PAGE_SIZE; i++) {
		opnd_a0[i] = (u8)(0xa5 ^ i);
		opnd_a1[i] = (u8)(0x5a ^ (i * 7));
	}
	*opnd_pte1 = opnd_pte1_ok;
	invlpg((void *)(OPND_VA + PAGE_SIZE));
	memcpy(opnd_im0, opnd_a0, PAGE_SIZE);
	memcpy(opnd_im1, opnd_a1, PAGE_SIZE);
	return (true);
}

/* scrive i byte dell'operando (a cavallo) tramite gli alias, e li riporta nelle immagini attese */
static void opnd_metti(u64 off, const void *v, int len)
{
	const u8 *b = v;
	int i;

	for (i = 0; i < len; i++) {
		u64 o = off + i;
		if (o < PAGE_SIZE)
			opnd_a0[o] = opnd_im0[o] = b[i];
		else
			opnd_a1[o - PAGE_SIZE] = opnd_im1[o - PAGE_SIZE] = b[i];
	}
}

/* l'operando scritto dall'istruzione, nelle immagini attese */
static void opnd_atteso_scritto(u64 off, const void *v, int len)
{
	const u8 *b = v;
	int i;

	for (i = 0; i < len; i++) {
		u64 o = off + i;
		if (o < PAGE_SIZE)
			opnd_im0[o] = b[i];
		else
			opnd_im1[o - PAGE_SIZE] = b[i];
	}
}

enum { OI_VMPTRST, OI_VMPTRLD, OI_VMCLEAR, OI_VMREAD, OI_VMWRITE, OI_INVVPID, OI_INVEPT, OI_VMREAD_R, OI_VMWRITE_R };
static const char *opnd_inome[] = { "VMPTRST", "VMPTRLD", "VMCLEAR", "VMREAD", "VMWRITE", "INVVPID", "INVEPT", "VMREAD_R",
    "VMWRITE_R" };
/* stadio 10: forme registro di VMREAD/VMWRITE (destinazione con sentinella; valore da scrivere) */
#define OPND_DEST_SENT	0x5a5a5a5a5a5a5a5aULL
static u64 opnd_r_dest, opnd_r_val;

/* UNA istruzione VMX con l'operando a p; RFLAGS con CF e ZF accesi prima (VMsucceed li spegne). Vettore, 0 = nessuna */
static unsigned opnd_esegui(int istr, void *p, u64 reg, u64 *rfl, u64 *err)
{
	u64 f = read_rflags() | OPND_F, fo = 0;

	switch (istr) {
	case OI_VMPTRST:
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmptrst (%[p])\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p) : "memory", "cc");
		break;
	case OI_VMPTRLD:
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmptrld (%[p])\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p) : "memory", "cc");
		break;
	case OI_VMCLEAR:
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmclear (%[p])\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p) : "memory", "cc");
		break;
	case OI_VMREAD:			/* reg = codifica del campo */
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmread %[r], (%[p])\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p), [r] "r"(reg) : "memory", "cc");
		break;
	case OI_VMWRITE:		/* reg = codifica del campo */
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmwrite (%[p]), %[r]\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p), [r] "r"(reg) : "memory", "cc");
		break;
	case OI_INVVPID:		/* reg = tipo */
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "invvpid (%[p]), %[r]\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p), [r] "r"(reg) : "memory", "cc");
		break;
	case OI_INVEPT:			/* reg = tipo */
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "invept (%[p]), %[r]\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [p] "r"(p), [r] "r"(reg) : "memory", "cc");
		break;
	case OI_VMREAD_R:		/* reg = campo; destinazione in opnd_r_dest (sentinella prima) */
		opnd_r_dest = OPND_DEST_SENT;
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmread %[r], %[d]\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo), [d] "+r"(opnd_r_dest) : [f] "r"(f), [r] "r"(reg) : "memory", "cc");
		break;
	case OI_VMWRITE_R:		/* reg = campo; valore in opnd_r_val */
		asm volatile("push %[f]; popf\n\t" ASM_TRY("1f") "vmwrite %[v], %[r]\n\t" "1: pushf; pop %[o]"
		    : [o] "=r"(fo) : [f] "r"(f), [v] "r"(opnd_r_val), [r] "r"(reg) : "memory", "cc");
		break;
	}
	*rfl = fo;
	*err = exception_error_code();
	return (exception_vector());
}

/* un caso: esito osservato contro atteso (vec 0 = VMsucceed, 0x100 = VMfailValid col numero in 'vmerr', 14 = #PF) */
static void opnd_caso(const char *fase, int istr, u64 off, u64 reg, const char *var, unsigned vec_att, u64 err_att,
    u64 cr2_att, u64 vmerr_att, const char *nota)
{
	u64 rfl, err, cr2, vmerr = 0;
	unsigned vec;
	bool ok, mem;

	write_cr2(0x5a5a5a5a5a5a5a5aULL);
	vec = opnd_esegui(istr, (void *)(OPND_VA + off), reg, &rfl, &err);
	cr2 = read_cr2();
	*opnd_pte1 = opnd_pte1_ok;			/* le mappe di prima, PRIMA di guardare le pagine */
	invlpg((void *)(OPND_VA + PAGE_SIZE));
	if (vec == 0 && (rfl & X86_EFLAGS_ZF))
		vmerr = vmcs_read(VMX_INST_ERROR);
	mem = !memcmp(opnd_a0, opnd_im0, PAGE_SIZE) && !memcmp(opnd_a1, opnd_im1, PAGE_SIZE);
	if (vec_att == 0x100)
		ok = vec == 0 && (rfl & X86_EFLAGS_ZF) && !(rfl & X86_EFLAGS_CF) && vmerr == vmerr_att && mem;
	else if (vec_att == 0)
		ok = vec == 0 && !(rfl & OPND_F) && mem;
	else
		ok = vec == vec_att && (vec != 14 || (err == err_att && cr2 == cr2_att)) && mem;
	opnd_n++;
	if (!ok)
		opnd_err++;
	printf("OPND CASO %s %d %s off=%#lx var=%s vec=%u err=%#lx cr2=%#lx rflags=%#lx vmerr=%lu memoria=%s "
	    "atteso(vec=%#x err=%#lx cr2=%#lx vmerr=%lu) %s -> %s\n", fase, opnd_n, opnd_inome[istr], (unsigned long)off,
	    var, vec, (unsigned long)err, vec == 14 ? (unsigned long)cr2 : 0UL, (unsigned long)rfl,
	    (unsigned long)vmerr, mem ? "come_attesa" : "DIVERSA", vec_att, (unsigned long)err_att,
	    (unsigned long)cr2_att, (unsigned long)vmerr_att, nota, ok ? "OK" : "ERRATO");
}

static u64 opnd_phys(struct vmcs *v) { return (virt_to_phys(v)); }

static const u64 opnd_offs_8[] = { 0xffc, 0xff9, 0xfff, 0x100 };
static const u64 opnd_offs_16[] = { 0xff8, 0xff1, 0x100 };

/* quanti casi e controlli fa UN passaggio di opnd_fase con queste capacita' */
static void opnd_conta_fase(int *casi, int *controlli)
{
	int iv = is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL) ? 1 : 0;
	int ie = is_invept_type_supported(INVEPT_SINGLE) ? 2 : 0;

	*casi += (int)ARRAY_SIZE(opnd_offs_8) * 5 + (int)ARRAY_SIZE(opnd_offs_16) * (iv + ie);
	*controlli += (int)ARRAY_SIZE(opnd_offs_8) * 3;
}

/* F1 (e la base per F2): ogni istruzione a cavallo, con lo stato iniziale esplicito; 'guasto': 0 nessuno,
 * 1 P1 non presente, 2 P1 sola lettura */
static void opnd_fase(const char *fase, int guasto)
{
	const char *var = guasto == 1 ? "P1_assente" : guasto == 2 ? "P1_sola_lettura" : "ok";
	u64 cur = opnd_phys(opnd_cur), tmp = opnd_phys(opnd_tmp), v, d[2];
	u64 eptp_ok, eptp_no;
	size_t i;

	/* con P1 guasto: #PF se l'operando la tocca (CR2 = inizio di P1), altrimenti l'esito normale */
#define OPND_GUASTO(o, l, w)	(guasto == 1 ? ((o) + (l) > PAGE_SIZE) : guasto == 2 ? ((w) && (o) + (l) > PAGE_SIZE) : 0)
#define OPND_ERR(w)		((guasto == 2 ? 1 : 0) | ((w) ? 2 : 0))
#define OPND_PREP()		do { if (!opnd_stato()) return; if (guasto == 1) *opnd_pte1 &= ~1ULL; if (guasto == 2) \
	*opnd_pte1 &= ~2ULL; invlpg((void *)(OPND_VA + PAGE_SIZE)); } while (0)
	for (i = 0; i < ARRAY_SIZE(opnd_offs_8); i++) {
		u64 o = opnd_offs_8[i];
		bool g;

		g = OPND_GUASTO(o, 8, 1);			/* VMPTRST: scrive il puntatore corrente */
		OPND_PREP();
		if (!g)
			opnd_atteso_scritto(o, &cur, 8);
		opnd_caso(fase, OI_VMPTRST, o, 0, var, g ? 14 : 0, OPND_ERR(1), OPND_VA + PAGE_SIZE, 0, "puntatore corrente");

		g = OPND_GUASTO(o, 8, 0);			/* VMPTRLD: il VMCS di lavoro diventa corrente */
		OPND_PREP();
		opnd_metti(o, &tmp, 8);
		opnd_caso(fase, OI_VMPTRLD, o, 0, var, g ? 14 : 0, OPND_ERR(0), OPND_VA + PAGE_SIZE, 0, "VMCS di lavoro");
		opnd_controllo(fase, "VMCS corrente dopo VMPTRLD", opnd_corrente(), g ? cur : tmp);
		if (!opnd_carica(opnd_cur, "ripristino del VMCS del framework"))
			return;

		/* VMCLEAR del VMCS di lavoro reso CORRENTE prima: l'effetto e' osservabile (nessun VMCS corrente dopo) */
		OPND_PREP();
		if (!opnd_carica(opnd_tmp, "VMCS di lavoro corrente prima del caso"))
			return;
		opnd_metti(o, &tmp, 8);
		opnd_caso(fase, OI_VMCLEAR, o, 0, var, g ? 14 : 0, OPND_ERR(0), OPND_VA + PAGE_SIZE, 0,
		    "VMCS di lavoro, corrente");
		opnd_controllo(fase, "VMCS corrente dopo VMCLEAR", opnd_corrente(), g ? tmp : OPND_NESSUNO);
		if (!opnd_carica(opnd_cur, "ripristino del VMCS del framework"))
			return;

		g = OPND_GUASTO(o, 8, 1);			/* VMREAD di GUEST_RIP del VMCS corrente verso memoria */
		OPND_PREP();
		v = vmcs_read(GUEST_RIP);
		if (!g)
			opnd_atteso_scritto(o, &v, 8);
		opnd_caso(fase, OI_VMREAD, o, GUEST_RIP, var, g ? 14 : 0, OPND_ERR(1), OPND_VA + PAGE_SIZE, 0, "GUEST_RIP");

		g = OPND_GUASTO(o, 8, 0);			/* VMWRITE di GUEST_RIP nel VMCS di lavoro (sentinella prima) */
		OPND_PREP();
		if (!opnd_carica(opnd_tmp, "VMCS di lavoro corrente prima del caso"))
			return;
		v = 0x1122334455667788ULL;
		opnd_metti(o, &v, 8);
		opnd_caso(fase, OI_VMWRITE, o, GUEST_RIP, var, g ? 14 : 0, OPND_ERR(0), OPND_VA + PAGE_SIZE, 0,
		    "GUEST_RIP del VMCS di lavoro");
		opnd_controllo(fase, "GUEST_RIP del VMCS di lavoro dopo VMWRITE", vmcs_read(GUEST_RIP),
		    g ? OPND_RIP_SENT : 0x1122334455667788ULL);
		if (!opnd_carica(opnd_cur, "ripristino del VMCS del framework"))
			return;
	}
	for (i = 0; i < ARRAY_SIZE(opnd_offs_16); i++) {
		u64 o = opnd_offs_16[i];
		bool g = OPND_GUASTO(o, 16, 0);

		if (is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL)) {
			d[0] = 1; d[1] = 0;			/* VPID 1 */
			OPND_PREP();
			opnd_metti(o, d, 16);
			opnd_caso(fase, OI_INVVPID, o, INVVPID_CONTEXT_GLOBAL, var, g ? 14 : 0, OPND_ERR(0),
			    OPND_VA + PAGE_SIZE, 0, "tipo 1, VPID 1");
		}
		if (is_invept_type_supported(INVEPT_SINGLE)) {
			eptp_ok = virt_to_phys(opnd_tmp) | 6 | (3 << 3);	/* WB, walk 4, niente A/D */
			eptp_no = (eptp_ok & ~7ULL) | 1;			/* tipo di memoria 1: non valido */
			d[0] = eptp_ok; d[1] = 0;
			OPND_PREP();
			opnd_metti(o, d, 16);
			opnd_caso(fase, OI_INVEPT, o, INVEPT_SINGLE, var, g ? 14 : 0, OPND_ERR(0), OPND_VA + PAGE_SIZE, 0,
			    "tipo 1, EPTP valido");
			d[0] = eptp_no;
			OPND_PREP();
			opnd_metti(o, d, 16);
			opnd_caso(fase, OI_INVEPT, o, INVEPT_SINGLE, var, g ? 14 : 0x100, OPND_ERR(0), OPND_VA + PAGE_SIZE,
			    28, "tipo 1, EPTP NON valido: VMfail 28 (invalidazione non misurata)");
		}
	}
#undef OPND_GUASTO
#undef OPND_ERR
#undef OPND_PREP
}

/*
 * STADIO 10, una volta in F1 (var=s10): K2 (in modo 64 bit un campo con i bit 63:32 accesi -> VMfail 12, in forma
 * memoria e registro; memoria, destinazione e campo invariati) e l'ordine m128 (tipo NON annunciato -> VMfail 28 PRIMA
 * della lettura del descrittore: descrittore a 0xff8 con P1 assente, quindi nessun #PF). INVVPID annuncia i tipi 0-3
 * (ept_vpid bit 40-43): il non annunciato e' solo >= 4; INVEPT annuncia 1 e 2: si provano 0 e 3.
 * Casi: 4 + invvpid1 + 2 * invept1; controlli: 3.
 */
#define OPND_S10_CONTROLLI	3
static int opnd_s10_casi(void)
{
	return (4 + (is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL) ? 1 : 0) +
	    (is_invept_type_supported(INVEPT_SINGLE) ? 2 : 0));
}
static void opnd_s10(void)
{
	u64 campo = GUEST_RIP | (1ULL << 32), v = 0x1122334455667788ULL, d[2] = { 0, 0 };
	static const u64 tipi_ept[] = { 0, 3 };
	size_t i;

	/* K2, VMREAD in memoria: VMfail 12, la memoria resta com'era */
	if (!opnd_stato())
		return;
	opnd_caso("F1", OI_VMREAD, 0x100, campo, "s10", 0x100, 0, 0, 12, "K2: campo con il bit 32 (memoria)");
	/* K2, VMWRITE dalla memoria nel VMCS di lavoro: VMfail 12, GUEST_RIP resta la sentinella */
	if (!opnd_stato() || !opnd_carica(opnd_tmp, "VMCS di lavoro corrente (K2 VMWRITE)"))
		return;
	opnd_metti(0x100, &v, 8);
	opnd_caso("F1", OI_VMWRITE, 0x100, campo, "s10", 0x100, 0, 0, 12, "K2: campo con il bit 32 (memoria)");
	opnd_controllo("F1", "GUEST_RIP invariato dopo VMWRITE K2 (memoria)", vmcs_read(GUEST_RIP), OPND_RIP_SENT);
	if (!opnd_carica(opnd_cur, "ripristino del VMCS del framework (K2)"))
		return;
	/* K2, VMREAD in registro: VMfail 12, la destinazione resta la sentinella (l'SDM non la scrive) */
	if (!opnd_stato())
		return;
	opnd_caso("F1", OI_VMREAD_R, 0x100, campo, "s10", 0x100, 0, 0, 12, "K2: campo con il bit 32 (registro)");
	opnd_controllo("F1", "destinazione di VMREAD K2 invariata (registro)", opnd_r_dest, OPND_DEST_SENT);
	/* K2, VMWRITE da registro nel VMCS di lavoro: VMfail 12, GUEST_RIP resta la sentinella */
	if (!opnd_stato() || !opnd_carica(opnd_tmp, "VMCS di lavoro corrente (K2 VMWRITE registro)"))
		return;
	opnd_r_val = v;
	opnd_caso("F1", OI_VMWRITE_R, 0x100, campo, "s10", 0x100, 0, 0, 12, "K2: campo con il bit 32 (registro)");
	opnd_controllo("F1", "GUEST_RIP invariato dopo VMWRITE K2 (registro)", vmcs_read(GUEST_RIP), OPND_RIP_SENT);
	if (!opnd_carica(opnd_cur, "ripristino del VMCS del framework (K2 registro)"))
		return;
	/* ordine m128: tipo non annunciato con descrittore illeggibile -> VMfail 28, nessun #PF */
	if (is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL)) {
		if (!opnd_stato())
			return;
		*opnd_pte1 &= ~1ULL; invlpg((void *)(OPND_VA + PAGE_SIZE));
		opnd_metti(0xff8, d, 16);
		opnd_caso("F1", OI_INVVPID, 0xff8, 4, "s10", 0x100, 0, 0, 28,
		    "ordine m128: tipo 4 non annunciato, P1 assente: VMfail senza #PF");
	}
	for (i = 0; is_invept_type_supported(INVEPT_SINGLE) && i < ARRAY_SIZE(tipi_ept); i++) {
		if (!opnd_stato())
			return;
		*opnd_pte1 &= ~1ULL; invlpg((void *)(OPND_VA + PAGE_SIZE));
		opnd_metti(0xff8, d, 16);
		opnd_caso("F1", OI_INVEPT, 0xff8, tipi_ept[i], "s10", 0x100, 0, 0, 28,
		    "ordine m128: tipo non annunciato, P1 assente: VMfail senza #PF");
	}
}

/* F3: CPL 3 (in questo KUT usermode_func non ha argomenti: operando e tipo in due globali) */
static u64 opnd_u_p, opnd_u_t;
static uint64_t opnd_u_vmptrld(void)
{
	asm volatile("vmptrld (%0)" : : "r"(opnd_u_p) : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_invvpid(void)
{
	asm volatile("invvpid (%0), %1" : : "r"(opnd_u_p), "r"(opnd_u_t) : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_vmxon(void)
{
	asm volatile("vmxon (%0)" : : "r"(opnd_u_p) : "memory", "cc");
	return (0);
}
/* parere Opus §3: le altre ragioni di nested_insn_guard (VMXON resta fuori dal guard). Con il guard rotto le
 * istruzioni senza operando cambierebbero lo stato VMX dell'L1: per questo VMXOFF/VMLAUNCH/VMRESUME sono in CODA. */
static u64 opnd_u_scratch[2] __attribute__((aligned(16)));
static uint64_t opnd_u_vmclear(void)
{
	asm volatile("vmclear (%0)" : : "r"(opnd_u_p) : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_vmptrst(void)
{
	asm volatile("vmptrst (%0)" : : "r"(opnd_u_scratch) : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_invept(void)
{
	asm volatile("invept (%0), %1" : : "r"(opnd_u_p), "r"(opnd_u_t) : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_vmread(void)
{
	u64 v = 0;

	asm volatile("vmread %1, %0" : "=r"(v) : "r"((u64)GUEST_RIP) : "memory", "cc");
	return (v);
}
static uint64_t opnd_u_vmwrite(void)
{
	asm volatile("vmwrite %0, %1" : : "r"(0x1122334455667788ULL), "r"((u64)GUEST_RIP) : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_vmxoff(void)
{
	asm volatile("vmxoff" : : : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_vmlaunch(void)
{
	asm volatile("vmlaunch" : : : "memory", "cc");
	return (0);
}
static uint64_t opnd_u_vmresume(void)
{
	asm volatile("vmresume" : : : "memory", "cc");
	return (0);
}
#define OPND_F3_CASI	12
static void opnd_f3(void)
{
	static u64 op[2] __attribute__((aligned(16)));
	bool gp;
	struct { const char *nome; usermode_func f; u64 a2; } u[OPND_F3_CASI] = {
		{ "VMPTRLD", opnd_u_vmptrld, 0 }, { "INVVPID", opnd_u_invvpid, INVVPID_CONTEXT_GLOBAL },
		{ "INVVPID_tipo4_non_annunciato", opnd_u_invvpid, 4 }, { "VMXON_VMX_gia_attiva", opnd_u_vmxon, 0 },
		{ "VMCLEAR", opnd_u_vmclear, 0 }, { "VMPTRST", opnd_u_vmptrst, 0 },
		{ "INVEPT", opnd_u_invept, INVEPT_SINGLE }, { "VMREAD", opnd_u_vmread, 0 }, { "VMWRITE", opnd_u_vmwrite, 0 },
		{ "VMXOFF", opnd_u_vmxoff, 0 }, { "VMLAUNCH", opnd_u_vmlaunch, 0 }, { "VMRESUME", opnd_u_vmresume, 0 },
	};
	size_t i;

	op[0] = opnd_phys(opnd_tmp);
	for (i = 0; i < ARRAY_SIZE(u); i++) {
		if (!opnd_stato())
			return;
		gp = false;
		opnd_u_p = (u64)op;
		opnd_u_t = u[i].a2;
		run_in_user(u[i].f, GP_VECTOR, 0, 0, 0, 0, &gp);
		opnd_n++;
		if (!gp)
			opnd_err++;
		printf("OPND CASO F3 %d %s cpl3 #GP=%s atteso(#GP prima di ogni accesso e di ogni VMfail) -> %s\n",
		    opnd_n, u[i].nome, gp ? "si" : "NO", gp ? "OK" : "ERRATO");
	}
}

/* F4: TERMINALE. La seconda pagina su un GPA senza memoria: l'host chiude il latch (stadio 4) e VM_RUN = 95. */
static void opnd_f4(void)
{
	u64 ram = fwcfg_get_u64(FW_CFG_RAM_SIZE), gpa = (ram + (1ULL << 30)) & ~((1ULL << 30) - 1), rfl, err;

	if (!opnd_stato())
		return;
	*opnd_pte1 = (gpa & PT_ADDR_MASK) | (opnd_pte1_ok & ~PT_ADDR_MASK);
	invlpg((void *)(OPND_VA + PAGE_SIZE));
	printf("OPND F4 INIZIO ram=%#lx P1->gpa %#lx (oltre la RAM) pte=%#lx: VMPTRST a %#lx, atteso NESSUN ritorno\n",
	    (unsigned long)ram, (unsigned long)gpa, (unsigned long)*opnd_pte1, (unsigned long)(OPND_VA + 0xffc));
	(void)opnd_esegui(OI_VMPTRST, (void *)(OPND_VA + 0xffc), 0, &rfl, &err);
	opnd_err++;
	printf("OPND F4 RITORNATO vec=%u rflags=%#lx -> ERRATO\n", exception_vector(), (unsigned long)rfl);
}

static void vmx_opnd_test(void)
{
	char piano[32];
	int c, l = 0, f1 = 0, f2 = 0, f3 = 0, f4 = 0, casi = 0, controlli = 0;
	u64 p0, p1;
	u8 *p[3];

	/* prerequisiti: CR0.WP per i casi di sola lettura; P0 e P1 fisicamente non adiacenti nei due versi */
	write_cr0(read_cr0() | X86_CR0_WP);
	p[0] = alloc_page(); p[1] = alloc_page(); p[2] = alloc_page();
	opnd_a0 = p[0];
	opnd_a1 = p[2];
	p0 = virt_to_phys(opnd_a0); p1 = virt_to_phys(opnd_a1);
	install_page(current_page_table(), p0, (void *)OPND_VA);
	opnd_pte1 = install_page(current_page_table(), p1, (void *)(OPND_VA + PAGE_SIZE));
	opnd_pte1_ok = *opnd_pte1;
	opnd_tmp = alloc_page();
	vmcs_save(&opnd_cur);
	printf("OPND INIZIO P0 %#lx P1 %#lx VMCS corrente %#lx di lavoro %#lx ept_vpid %#lx cr0 %#lx (WP=%d)\n",
	    (unsigned long)p0, (unsigned long)p1, (unsigned long)virt_to_phys(opnd_cur),
	    (unsigned long)virt_to_phys(opnd_tmp), (unsigned long)ept_vpid.val, read_cr0(), !!(read_cr0() & X86_CR0_WP));
	/* stadio 10, K6 (parere Opus sullo stadio 10, 1.1): L0 da' #UD a INVEPT/INVVPID se "enable EPT"/"enable VPID"
	 * non sono consentiti in IA32_VMX_PROCBASED_CTLS2 (bit alti 1 e 5) o se i bit 20/32 di EPT_VPID_CAP sono spenti.
	 * Entrambe le MSR le serve L0 dalla tabella virtuale (vmx_msr.c): la loro lettura qui e' l'evidenza runtime. */
	opnd_ctls2 = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	printf("OPND MSR ctls2 %#lx (enable EPT %d, enable VPID %d) ept_vpid %#lx (INVEPT %d, INVVPID %d)\n",
	    (unsigned long)opnd_ctls2, !!((opnd_ctls2 >> 32) & (1u << 1)), !!((opnd_ctls2 >> 32) & (1u << 5)),
	    (unsigned long)ept_vpid.val, !!(ept_vpid.val & (1ull << 20)), !!(ept_vpid.val & (1ull << 32)));
	if ((is_invept_type_supported(INVEPT_SINGLE) && (!((opnd_ctls2 >> 32) & (1u << 1)) || !(ept_vpid.val & (1ull << 20)))) ||
	    (is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL) && (!((opnd_ctls2 >> 32) & (1u << 5)) ||
	    !(ept_vpid.val & (1ull << 32))))) {
		opnd_prereq("K6: INVEPT/INVVPID annunciate ma non esposte (CTLS2 enable EPT/VPID o EPT_VPID_CAP 20/32)");
		report(false, "%s: prerequisiti K6", __func__);
		return;
	}
	/* parere Opus §3: il caso "EPTP valido" usa WB (cap bit 14) e walk a 4 livelli (bit 6): se l'L1 non li vede
	 * annunciati quel caso fallirebbe per un motivo estraneo all'operando */
	if (is_invept_type_supported(INVEPT_SINGLE) &&
	    (!(ept_vpid.val & EPT_CAP_WB) || !(ept_vpid.val & EPT_CAP_PWL4))) {
		opnd_prereq("EPT: WB o walk a 4 livelli non annunciati all'L1 (caso EPTP valido non significativo)");
		report(false, "%s: prerequisiti EPT", __func__);
		return;
	}
	if (p1 == p0 + PAGE_SIZE || p0 == p1 + PAGE_SIZE || !(read_cr0() & X86_CR0_WP)) {
		opnd_prereq("P0/P1 fisicamente adiacenti o CR0.WP spento: test fermato");
		report(false, "%s: prerequisiti", __func__);
		return;
	}
	printf("OPND PIANO? (F1,F2,F3 oppure F4)\n");
	for (;;) {
		c = opnd_getc();
		if (c < 0 || c == '\n' || l >= (int)sizeof(piano) - 1)
			break;
		if (c != '\r')
			piano[l++] = (char)c;
	}
	piano[l] = 0;
	f1 = !!strstr(piano, "F1"); f2 = !!strstr(piano, "F2"); f3 = !!strstr(piano, "F3"); f4 = !!strstr(piano, "F4");
	printf("OPND PIANO \"%s\" F1=%d F2=%d F3=%d F4=%d\n", piano, f1, f2, f3, f4);
	if ((f4 && (f1 || f2 || f3)) || !(f1 || f2 || f3 || f4)) {
		opnd_prereq("piano non ammesso (F4 va da sola; piano vuoto)");
		report(false, "%s: piano rifiutato", __func__);
		return;
	}
	if (f1) {
		opnd_conta_fase(&casi, &controlli);
		casi += opnd_s10_casi();		/* stadio 10 */
		controlli += OPND_S10_CONTROLLI;
	}
	if (f2) {
		opnd_conta_fase(&casi, &controlli);
		opnd_conta_fase(&casi, &controlli);
	}
	if (f3)
		casi += OPND_F3_CASI;
	printf("OPND ATTESI casi=%d controlli=%d invvpid1=%d invept1=%d\n", casi, controlli,
	    !!is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL), !!is_invept_type_supported(INVEPT_SINGLE));
	if (f1) {
		opnd_fase("F1", 0);
		opnd_s10();
	}
	if (f2) {
		opnd_fase("F2", 1);
		opnd_fase("F2", 2);
	}
	if (f3)
		opnd_f3();
	if (f4)
		opnd_f4();
	if (!opnd_fermo)
		(void)opnd_carica(opnd_cur, "ripristino finale del VMCS del framework");
	printf("OPND FINE casi=%d controlli=%d errati=%d\n", opnd_n, opnd_nc, opnd_err);
	report(opnd_err == 0 && opnd_n == casi && opnd_nc == controlli && !f4, "%s: %d casi, %d controlli, %d errati",
	    __func__, opnd_n, opnd_nc, opnd_err);
}
