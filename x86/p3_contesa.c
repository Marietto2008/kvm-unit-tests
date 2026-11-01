/*
 * p3_contesa.c -- Claude 01/11/2026. Test di PROVOCAZIONE per P3 (stadio 11): contesa persistente sul walk delle
 * tabelle dell'L1 durante l'emulazione di un'istruzione VMX con operando in memoria.
 *
 * Questo programma gira come L1 (con VMX esposto da L0). La CPU 0 esegue VMXON e poi VMPTRST verso un operando in
 * una pagina P mappata da una voce di tabella (PTE) a 4K con A=0 e D=0. L'istruzione esce verso L0, che traduce
 * l'indirizzo camminando le tabelle di QUESTO programma e deve accendere A e D sulla PTE con un cmpset. Intanto la
 * CPU 1 riscrive la stessa PTE in un ciclo stretto con un CONTATORE nei bit ignorati dall'hardware e dal walker di L0
 * (9-11 e 52-58: 1024 valori distinti), tenendo A=D=0: il cmpset di L0 fallisce quasi sempre, cioe' la contesa e'
 * persistente finche' lo scrittore non si ferma da solo (dopo DURATA cicli di TSC).
 * v2 (01/11, dopo la sessione provocazione-p3-1, INCONCLUSIVA): la v1 alternava DUE soli valori (bit 9): il cmpset
 * trovava il valore letto circa una volta su due (ABA) e riusciva; 64 fallimenti di fila non arrivavano mai.
 *
 * Atteso sullo stadio 11: L0 conta i walk interrotti (hw.vmm.gla2gpa_restart_capped sale), l'istruzione riparte
 * servita (nessun panic, host reattivo) e, fermato lo scrittore, VMPTRST completa con il valore giusto (nessuna VMCS
 * corrente dopo VMXON: 0xffffffffffffffff). Sullo stadio 10 lo stesso test terrebbe il thread del vCPU nel kernel per
 * tutta la contesa (il difetto P3): NON va eseguito li'.
 *
 * Le righe "P3 ..." sono per il runner: tempi in cicli di TSC, scritture dello scrittore, esito di ogni round.
 */
#include "libcflat.h"
#include "smp.h"
#include "processor.h"
#include "msr.h"
#include "vm.h"
#include "alloc_page.h"
#include "vmalloc.h"
#include "asm/page.h"

#define BIT9		(1ull << 9)
/* il contatore nei bit ignorati: 3 bit in 11:9 e 7 bit in 58:52 */
#define CONTA(c)	((((c) & 7ull) << 9) | ((((c) >> 3) & 0x7full) << 52))
#define MASCHERA_C	CONTA(0x3ffull)
#define DURATA		3000000000ull	/* cicli di TSC di contesa per round (circa 1 s) */
#define ROUND		3
#define NESSUNA_VMCS	0xffffffffffffffffull

static volatile pteval_t *pte;
static pteval_t v0, v1;
static volatile int pronto, finito;
static volatile u64 scritture;

static void scrittore(void *dati)
{
	u64 fine, n = 0;
	int i;

	(void)dati;
	fine = rdtsc() + DURATA;
	pronto = 1;
	do {
		for (i = 0; i < 1000; i++)
			*pte = v0 | CONTA(n + i);	/* mai due valori uguali consecutivi; periodo 1024 */
		n += 1000;
	} while (rdtsc() < fine);
	*pte = v0;			/* A=D=0: il prossimo walk di L0 li accende senza piu' contesa */
	scritture = n;
	finito = 1;
}

static int vmxon(u64 fisico)
{
	bool ret;

	asm volatile("vmxon %1; setbe %0" : "=q"(ret) : "m"(fisico) : "cc", "memory");
	return ret;
}

static int vmptrst(u64 *dove)
{
	bool ret;

	asm volatile("vmptrst %1; setbe %0" : "=q"(ret), "=m"(*dove) : : "cc", "memory");
	return ret;
}

int main(void)
{
	u64 *regione, *op, t0, t1, fc;
	pgd_t *cr3;
	void *va;
	phys_addr_t pa;
	int r, k;

	if (cpu_count() < 2) {
		report_skip("servono 2 CPU (-smp 2): trovate %d", cpu_count());
		return report_summary();
	}
	setup_vm();

	/* la pagina dell'operando, con una PTE a 4K sua */
	pa = virt_to_phys(alloc_page());
	va = alloc_vpage();
	cr3 = (pgd_t *)phys_to_virt(read_cr3());
	install_page(cr3, pa, va);
	pte = get_pte(cr3, va);
	report(pte != NULL && (*pte & PT_PRESENT_MASK) && (*pte & PT_PAGE_SIZE_MASK) == 0,
	       "PTE a 4K della pagina dell'operando");
	op = (u64 *)((char *)va + 0x100);
	v0 = *pte & ~(PT_AD_MASK | MASCHERA_C);
	v1 = v0 | BIT9;
	printf("P3 pte %#lx v0 %#lx v1 %#lx\n", (ulong)pte, (ulong)v0, (ulong)v1);

	/* VMX acceso come in x86/vmx.c (enable_vmx, init_vmx) */
	fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((fc & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX) == 0)
		wrmsr(MSR_IA32_FEATURE_CONTROL, FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX | FEATURE_CONTROL_LOCKED);
	write_cr0((read_cr0() & rdmsr(MSR_IA32_VMX_CR0_FIXED1)) | rdmsr(MSR_IA32_VMX_CR0_FIXED0));
	write_cr4((read_cr4() & rdmsr(MSR_IA32_VMX_CR4_FIXED1)) | rdmsr(MSR_IA32_VMX_CR4_FIXED0) | X86_CR4_VMXE);
	regione = alloc_page();
	*(u32 *)regione = (u32)rdmsr(MSR_IA32_VMX_BASIC);
	r = vmxon(virt_to_phys(regione));
	report(r == 0, "VMXON");
	if (r != 0)
		return report_summary();

	/* riferimento senza contesa */
	*op = 0x5a5a5a5a5a5a5a5aull;
	*pte = v0;
	t0 = rdtsc();
	r = vmptrst(op);
	t1 = rdtsc();
	report(r == 0 && *op == NESSUNA_VMCS, "VMPTRST senza contesa (%#lx)", (ulong)*op);
	printf("P3 riferimento cicli %lu\n", (ulong)(t1 - t0));

	/* i round con la contesa */
	for (k = 1; k <= ROUND; k++) {
		*op = 0x5a5a5a5a5a5a5a5aull;
		*pte = v0;
		pronto = finito = 0;
		scritture = 0;
		on_cpu_async(1, scrittore, NULL);
		while (!pronto)
			pause();
		t0 = rdtsc();
		r = vmptrst(op);	/* bloccata (servita) finche' lo scrittore riscrive la PTE */
		t1 = rdtsc();
		while (!finito)
			pause();
		report(r == 0 && *op == NESSUNA_VMCS, "round %d: VMPTRST completa con il valore giusto (%#lx)", k,
		       (ulong)*op);
		printf("P3 round %d cicli %lu durata %lu scritture %lu\n", k, (ulong)(t1 - t0), (ulong)DURATA,
		       (ulong)scritture);
	}

	/* dopo: di nuovo senza contesa */
	*op = 0x5a5a5a5a5a5a5a5aull;
	r = vmptrst(op);
	report(r == 0 && *op == NESSUNA_VMCS, "VMPTRST dopo la contesa");
	asm volatile("vmxoff" ::: "cc", "memory");
	return report_summary();
}
