/*
 * lemonades CPU0 bring-up only. Append to the already initialized Linux ramoops
 * console at 0xb0000000..0xb0200000. Never touch its adjacent pmsg region.
 * No stack, allocation, calls, UART or firmware services. x9..x17/NZCV scratch;
 * use only at the reviewed startup boundaries where those registers are dead.
 * The caller supplies a physical or explicitly mapped, uncached address.
 */
.macro LEMONADES_PUTC
	strb	w16, [x11, x12]
	add	x12, x12, #1
	cmp	x12, x17
	csel	x12, xzr, x12, eq
	add	x13, x13, #1
	cmp	x13, x17
	csel	x13, x17, x13, hi
.endmacro

.macro LEMONADES_HEX
	and	w16, w16, #15
	add	w16, w16, #48
	add	w14, w16, #39
	cmp	w16, #57
	csel	w16, w14, w16, hi
	LEMONADES_PUTC
.endmacro

/* x9=phase, x10=value, x11=console header. Preserve x0..x8, x18..x30. */
.macro LEMONADES_TRACE_BODY
	cbz	x11, 9f
	ldr	w16, [x11]
	mov	w17, #0x4244
	movk	w17, #0x4347, lsl #16
	cmp	w16, w17
	b.ne	9f
	mov	x17, #0xfff4
	movk	x17, #0x1f, lsl #16
	ldr	w12, [x11, #4]
	ldr	w13, [x11, #8]
	cmp	x13, x17
	b.hi	9f
	cmp	x12, x13
	b.hi	9f
	cmp	x12, x17
	csel	x12, xzr, x12, eq
	add	x11, x11, #12
	adr	x14, Llemonades_trace_prefix
1:
	ldrb	w16, [x14], #1
	cbz	w16, 2f
	LEMONADES_PUTC
	b	1b
2:
	lsr	w16, w9, #4
	LEMONADES_HEX
	mov	w16, w9
	LEMONADES_HEX
	mov	w16, #32
	LEMONADES_PUTC
	mov	x15, #60
3:
	lsr	x16, x10, x15
	LEMONADES_HEX
	subs	x15, x15, #4
	b.ge	3b
	mov	w16, #10
	LEMONADES_PUTC
	dsb	sy
	stur	w13, [x11, #-4]
	stur	w12, [x11, #-8]
	dsb	sy
9:
.endmacro

.macro LEMONADES_TRACE
	mov	x9, $0
	mov	x10, $1
	mov	x11, #0xb0000000
	LEMONADES_TRACE_BODY
.endmacro

/* C ABI wrapper: phase, value, console address. Leaf, no stack protector.
 * x3 is caller-saved. Mask IRQ/FIQ across each record so a timer observer
 * cannot interrupt another writer on CPU0. Restore the exact incoming DAIF.
 * The early assembly-only LEMONADES_TRACE macro remains unchanged.
 */
.text
.align 2
.globl EXT(lemonades_early_trace)
LEXT(lemonades_early_trace)
	mrs	x3, daif
	msr	daifset, #3
	mov	x9, x0
	mov	x10, x1
	mov	x11, x2
	LEMONADES_TRACE_BODY
	msr	daif, x3
	ret
Llemonades_trace_prefix:
	.asciz	"\nUMI XNU "
.align 2
