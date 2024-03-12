# Copyright (c) 2011-2016, Andy Polyakov <appro@openssl.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
#     * Redistributions of source code must retain copyright notices,
#      this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
#     * Neither the name of the Andy Polyakov nor the names of its
#      copyright holder and contributors may be used to endorse or
#      promote products derived from this software without specific
#      prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL), in which case the provisions of the GPL apply INSTEAD OF
# those given above.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# *** This file is auto-generated ***
#
.text	


.globl	sha512_block_data_order
.def	sha512_block_data_order;	.scl 2;	.type 32;	.endef
.p2align	4
sha512_block_data_order:
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_sha512_block_data_order:
	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx


	leaq	_gnutls_x86_cpuid_s(%rip),%r11
	movl	0(%r11),%r9d
	movl	4(%r11),%r10d
	movl	8(%r11),%r11d
	testl	$2048,%r10d
	jnz	.Lxop_shortcut
	andl	$296,%r11d
	cmpl	$296,%r11d
	je	.Lavx2_shortcut
	andl	$1073741824,%r9d
	andl	$268435968,%r10d
	orl	%r9d,%r10d
	cmpl	$1342177792,%r10d
	je	.Lavx_shortcut
	movq	%rsp,%rax

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	shlq	$4,%rdx
	subq	$128+32,%rsp
	leaq	(%rsi,%rdx,8),%rdx
	andq	$-64,%rsp
	movq	%rdi,128+0(%rsp)
	movq	%rsi,128+8(%rsp)
	movq	%rdx,128+16(%rsp)
	movq	%rax,152(%rsp)

.Lprologue:

	movq	0(%rdi),%rax
	movq	8(%rdi),%rbx
	movq	16(%rdi),%rcx
	movq	24(%rdi),%rdx
	movq	32(%rdi),%r8
	movq	40(%rdi),%r9
	movq	48(%rdi),%r10
	movq	56(%rdi),%r11
	jmp	.Lloop

.p2align	4
.Lloop:
	movq	%rbx,%rdi
	leaq	K512(%rip),%rbp
	xorq	%rcx,%rdi
	movq	0(%rsi),%r12
	movq	%r8,%r13
	movq	%rax,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r9,%r15

	xorq	%r8,%r13
	rorq	$5,%r14
	xorq	%r10,%r15

	movq	%r12,0(%rsp)
	xorq	%rax,%r14
	andq	%r8,%r15

	rorq	$4,%r13
	addq	%r11,%r12
	xorq	%r10,%r15

	rorq	$6,%r14
	xorq	%r8,%r13
	addq	%r15,%r12

	movq	%rax,%r15
	addq	(%rbp),%r12
	xorq	%rax,%r14

	xorq	%rbx,%r15
	rorq	$14,%r13
	movq	%rbx,%r11

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r11
	addq	%r12,%rdx
	addq	%r12,%r11

	leaq	8(%rbp),%rbp
	addq	%r14,%r11
	movq	8(%rsi),%r12
	movq	%rdx,%r13
	movq	%r11,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r8,%rdi

	xorq	%rdx,%r13
	rorq	$5,%r14
	xorq	%r9,%rdi

	movq	%r12,8(%rsp)
	xorq	%r11,%r14
	andq	%rdx,%rdi

	rorq	$4,%r13
	addq	%r10,%r12
	xorq	%r9,%rdi

	rorq	$6,%r14
	xorq	%rdx,%r13
	addq	%rdi,%r12

	movq	%r11,%rdi
	addq	(%rbp),%r12
	xorq	%r11,%r14

	xorq	%rax,%rdi
	rorq	$14,%r13
	movq	%rax,%r10

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r10
	addq	%r12,%rcx
	addq	%r12,%r10

	leaq	24(%rbp),%rbp
	addq	%r14,%r10
	movq	16(%rsi),%r12
	movq	%rcx,%r13
	movq	%r10,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rdx,%r15

	xorq	%rcx,%r13
	rorq	$5,%r14
	xorq	%r8,%r15

	movq	%r12,16(%rsp)
	xorq	%r10,%r14
	andq	%rcx,%r15

	rorq	$4,%r13
	addq	%r9,%r12
	xorq	%r8,%r15

	rorq	$6,%r14
	xorq	%rcx,%r13
	addq	%r15,%r12

	movq	%r10,%r15
	addq	(%rbp),%r12
	xorq	%r10,%r14

	xorq	%r11,%r15
	rorq	$14,%r13
	movq	%r11,%r9

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r9
	addq	%r12,%rbx
	addq	%r12,%r9

	leaq	8(%rbp),%rbp
	addq	%r14,%r9
	movq	24(%rsi),%r12
	movq	%rbx,%r13
	movq	%r9,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rcx,%rdi

	xorq	%rbx,%r13
	rorq	$5,%r14
	xorq	%rdx,%rdi

	movq	%r12,24(%rsp)
	xorq	%r9,%r14
	andq	%rbx,%rdi

	rorq	$4,%r13
	addq	%r8,%r12
	xorq	%rdx,%rdi

	rorq	$6,%r14
	xorq	%rbx,%r13
	addq	%rdi,%r12

	movq	%r9,%rdi
	addq	(%rbp),%r12
	xorq	%r9,%r14

	xorq	%r10,%rdi
	rorq	$14,%r13
	movq	%r10,%r8

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r8
	addq	%r12,%rax
	addq	%r12,%r8

	leaq	24(%rbp),%rbp
	addq	%r14,%r8
	movq	32(%rsi),%r12
	movq	%rax,%r13
	movq	%r8,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rbx,%r15

	xorq	%rax,%r13
	rorq	$5,%r14
	xorq	%rcx,%r15

	movq	%r12,32(%rsp)
	xorq	%r8,%r14
	andq	%rax,%r15

	rorq	$4,%r13
	addq	%rdx,%r12
	xorq	%rcx,%r15

	rorq	$6,%r14
	xorq	%rax,%r13
	addq	%r15,%r12

	movq	%r8,%r15
	addq	(%rbp),%r12
	xorq	%r8,%r14

	xorq	%r9,%r15
	rorq	$14,%r13
	movq	%r9,%rdx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rdx
	addq	%r12,%r11
	addq	%r12,%rdx

	leaq	8(%rbp),%rbp
	addq	%r14,%rdx
	movq	40(%rsi),%r12
	movq	%r11,%r13
	movq	%rdx,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rax,%rdi

	xorq	%r11,%r13
	rorq	$5,%r14
	xorq	%rbx,%rdi

	movq	%r12,40(%rsp)
	xorq	%rdx,%r14
	andq	%r11,%rdi

	rorq	$4,%r13
	addq	%rcx,%r12
	xorq	%rbx,%rdi

	rorq	$6,%r14
	xorq	%r11,%r13
	addq	%rdi,%r12

	movq	%rdx,%rdi
	addq	(%rbp),%r12
	xorq	%rdx,%r14

	xorq	%r8,%rdi
	rorq	$14,%r13
	movq	%r8,%rcx

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rcx
	addq	%r12,%r10
	addq	%r12,%rcx

	leaq	24(%rbp),%rbp
	addq	%r14,%rcx
	movq	48(%rsi),%r12
	movq	%r10,%r13
	movq	%rcx,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r11,%r15

	xorq	%r10,%r13
	rorq	$5,%r14
	xorq	%rax,%r15

	movq	%r12,48(%rsp)
	xorq	%rcx,%r14
	andq	%r10,%r15

	rorq	$4,%r13
	addq	%rbx,%r12
	xorq	%rax,%r15

	rorq	$6,%r14
	xorq	%r10,%r13
	addq	%r15,%r12

	movq	%rcx,%r15
	addq	(%rbp),%r12
	xorq	%rcx,%r14

	xorq	%rdx,%r15
	rorq	$14,%r13
	movq	%rdx,%rbx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rbx
	addq	%r12,%r9
	addq	%r12,%rbx

	leaq	8(%rbp),%rbp
	addq	%r14,%rbx
	movq	56(%rsi),%r12
	movq	%r9,%r13
	movq	%rbx,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r10,%rdi

	xorq	%r9,%r13
	rorq	$5,%r14
	xorq	%r11,%rdi

	movq	%r12,56(%rsp)
	xorq	%rbx,%r14
	andq	%r9,%rdi

	rorq	$4,%r13
	addq	%rax,%r12
	xorq	%r11,%rdi

	rorq	$6,%r14
	xorq	%r9,%r13
	addq	%rdi,%r12

	movq	%rbx,%rdi
	addq	(%rbp),%r12
	xorq	%rbx,%r14

	xorq	%rcx,%rdi
	rorq	$14,%r13
	movq	%rcx,%rax

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rax
	addq	%r12,%r8
	addq	%r12,%rax

	leaq	24(%rbp),%rbp
	addq	%r14,%rax
	movq	64(%rsi),%r12
	movq	%r8,%r13
	movq	%rax,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r9,%r15

	xorq	%r8,%r13
	rorq	$5,%r14
	xorq	%r10,%r15

	movq	%r12,64(%rsp)
	xorq	%rax,%r14
	andq	%r8,%r15

	rorq	$4,%r13
	addq	%r11,%r12
	xorq	%r10,%r15

	rorq	$6,%r14
	xorq	%r8,%r13
	addq	%r15,%r12

	movq	%rax,%r15
	addq	(%rbp),%r12
	xorq	%rax,%r14

	xorq	%rbx,%r15
	rorq	$14,%r13
	movq	%rbx,%r11

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r11
	addq	%r12,%rdx
	addq	%r12,%r11

	leaq	8(%rbp),%rbp
	addq	%r14,%r11
	movq	72(%rsi),%r12
	movq	%rdx,%r13
	movq	%r11,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r8,%rdi

	xorq	%rdx,%r13
	rorq	$5,%r14
	xorq	%r9,%rdi

	movq	%r12,72(%rsp)
	xorq	%r11,%r14
	andq	%rdx,%rdi

	rorq	$4,%r13
	addq	%r10,%r12
	xorq	%r9,%rdi

	rorq	$6,%r14
	xorq	%rdx,%r13
	addq	%rdi,%r12

	movq	%r11,%rdi
	addq	(%rbp),%r12
	xorq	%r11,%r14

	xorq	%rax,%rdi
	rorq	$14,%r13
	movq	%rax,%r10

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r10
	addq	%r12,%rcx
	addq	%r12,%r10

	leaq	24(%rbp),%rbp
	addq	%r14,%r10
	movq	80(%rsi),%r12
	movq	%rcx,%r13
	movq	%r10,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rdx,%r15

	xorq	%rcx,%r13
	rorq	$5,%r14
	xorq	%r8,%r15

	movq	%r12,80(%rsp)
	xorq	%r10,%r14
	andq	%rcx,%r15

	rorq	$4,%r13
	addq	%r9,%r12
	xorq	%r8,%r15

	rorq	$6,%r14
	xorq	%rcx,%r13
	addq	%r15,%r12

	movq	%r10,%r15
	addq	(%rbp),%r12
	xorq	%r10,%r14

	xorq	%r11,%r15
	rorq	$14,%r13
	movq	%r11,%r9

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r9
	addq	%r12,%rbx
	addq	%r12,%r9

	leaq	8(%rbp),%rbp
	addq	%r14,%r9
	movq	88(%rsi),%r12
	movq	%rbx,%r13
	movq	%r9,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rcx,%rdi

	xorq	%rbx,%r13
	rorq	$5,%r14
	xorq	%rdx,%rdi

	movq	%r12,88(%rsp)
	xorq	%r9,%r14
	andq	%rbx,%rdi

	rorq	$4,%r13
	addq	%r8,%r12
	xorq	%rdx,%rdi

	rorq	$6,%r14
	xorq	%rbx,%r13
	addq	%rdi,%r12

	movq	%r9,%rdi
	addq	(%rbp),%r12
	xorq	%r9,%r14

	xorq	%r10,%rdi
	rorq	$14,%r13
	movq	%r10,%r8

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r8
	addq	%r12,%rax
	addq	%r12,%r8

	leaq	24(%rbp),%rbp
	addq	%r14,%r8
	movq	96(%rsi),%r12
	movq	%rax,%r13
	movq	%r8,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rbx,%r15

	xorq	%rax,%r13
	rorq	$5,%r14
	xorq	%rcx,%r15

	movq	%r12,96(%rsp)
	xorq	%r8,%r14
	andq	%rax,%r15

	rorq	$4,%r13
	addq	%rdx,%r12
	xorq	%rcx,%r15

	rorq	$6,%r14
	xorq	%rax,%r13
	addq	%r15,%r12

	movq	%r8,%r15
	addq	(%rbp),%r12
	xorq	%r8,%r14

	xorq	%r9,%r15
	rorq	$14,%r13
	movq	%r9,%rdx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rdx
	addq	%r12,%r11
	addq	%r12,%rdx

	leaq	8(%rbp),%rbp
	addq	%r14,%rdx
	movq	104(%rsi),%r12
	movq	%r11,%r13
	movq	%rdx,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%rax,%rdi

	xorq	%r11,%r13
	rorq	$5,%r14
	xorq	%rbx,%rdi

	movq	%r12,104(%rsp)
	xorq	%rdx,%r14
	andq	%r11,%rdi

	rorq	$4,%r13
	addq	%rcx,%r12
	xorq	%rbx,%rdi

	rorq	$6,%r14
	xorq	%r11,%r13
	addq	%rdi,%r12

	movq	%rdx,%rdi
	addq	(%rbp),%r12
	xorq	%rdx,%r14

	xorq	%r8,%rdi
	rorq	$14,%r13
	movq	%r8,%rcx

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rcx
	addq	%r12,%r10
	addq	%r12,%rcx

	leaq	24(%rbp),%rbp
	addq	%r14,%rcx
	movq	112(%rsi),%r12
	movq	%r10,%r13
	movq	%rcx,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r11,%r15

	xorq	%r10,%r13
	rorq	$5,%r14
	xorq	%rax,%r15

	movq	%r12,112(%rsp)
	xorq	%rcx,%r14
	andq	%r10,%r15

	rorq	$4,%r13
	addq	%rbx,%r12
	xorq	%rax,%r15

	rorq	$6,%r14
	xorq	%r10,%r13
	addq	%r15,%r12

	movq	%rcx,%r15
	addq	(%rbp),%r12
	xorq	%rcx,%r14

	xorq	%rdx,%r15
	rorq	$14,%r13
	movq	%rdx,%rbx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rbx
	addq	%r12,%r9
	addq	%r12,%rbx

	leaq	8(%rbp),%rbp
	addq	%r14,%rbx
	movq	120(%rsi),%r12
	movq	%r9,%r13
	movq	%rbx,%r14
	bswapq	%r12
	rorq	$23,%r13
	movq	%r10,%rdi

	xorq	%r9,%r13
	rorq	$5,%r14
	xorq	%r11,%rdi

	movq	%r12,120(%rsp)
	xorq	%rbx,%r14
	andq	%r9,%rdi

	rorq	$4,%r13
	addq	%rax,%r12
	xorq	%r11,%rdi

	rorq	$6,%r14
	xorq	%r9,%r13
	addq	%rdi,%r12

	movq	%rbx,%rdi
	addq	(%rbp),%r12
	xorq	%rbx,%r14

	xorq	%rcx,%rdi
	rorq	$14,%r13
	movq	%rcx,%rax

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rax
	addq	%r12,%r8
	addq	%r12,%rax

	leaq	24(%rbp),%rbp
	jmp	.Lrounds_16_xx
.p2align	4
.Lrounds_16_xx:
	movq	8(%rsp),%r13
	movq	112(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rax
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	72(%rsp),%r12

	addq	0(%rsp),%r12
	movq	%r8,%r13
	addq	%r15,%r12
	movq	%rax,%r14
	rorq	$23,%r13
	movq	%r9,%r15

	xorq	%r8,%r13
	rorq	$5,%r14
	xorq	%r10,%r15

	movq	%r12,0(%rsp)
	xorq	%rax,%r14
	andq	%r8,%r15

	rorq	$4,%r13
	addq	%r11,%r12
	xorq	%r10,%r15

	rorq	$6,%r14
	xorq	%r8,%r13
	addq	%r15,%r12

	movq	%rax,%r15
	addq	(%rbp),%r12
	xorq	%rax,%r14

	xorq	%rbx,%r15
	rorq	$14,%r13
	movq	%rbx,%r11

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r11
	addq	%r12,%rdx
	addq	%r12,%r11

	leaq	8(%rbp),%rbp
	movq	16(%rsp),%r13
	movq	120(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r11
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	80(%rsp),%r12

	addq	8(%rsp),%r12
	movq	%rdx,%r13
	addq	%rdi,%r12
	movq	%r11,%r14
	rorq	$23,%r13
	movq	%r8,%rdi

	xorq	%rdx,%r13
	rorq	$5,%r14
	xorq	%r9,%rdi

	movq	%r12,8(%rsp)
	xorq	%r11,%r14
	andq	%rdx,%rdi

	rorq	$4,%r13
	addq	%r10,%r12
	xorq	%r9,%rdi

	rorq	$6,%r14
	xorq	%rdx,%r13
	addq	%rdi,%r12

	movq	%r11,%rdi
	addq	(%rbp),%r12
	xorq	%r11,%r14

	xorq	%rax,%rdi
	rorq	$14,%r13
	movq	%rax,%r10

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r10
	addq	%r12,%rcx
	addq	%r12,%r10

	leaq	24(%rbp),%rbp
	movq	24(%rsp),%r13
	movq	0(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r10
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	88(%rsp),%r12

	addq	16(%rsp),%r12
	movq	%rcx,%r13
	addq	%r15,%r12
	movq	%r10,%r14
	rorq	$23,%r13
	movq	%rdx,%r15

	xorq	%rcx,%r13
	rorq	$5,%r14
	xorq	%r8,%r15

	movq	%r12,16(%rsp)
	xorq	%r10,%r14
	andq	%rcx,%r15

	rorq	$4,%r13
	addq	%r9,%r12
	xorq	%r8,%r15

	rorq	$6,%r14
	xorq	%rcx,%r13
	addq	%r15,%r12

	movq	%r10,%r15
	addq	(%rbp),%r12
	xorq	%r10,%r14

	xorq	%r11,%r15
	rorq	$14,%r13
	movq	%r11,%r9

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r9
	addq	%r12,%rbx
	addq	%r12,%r9

	leaq	8(%rbp),%rbp
	movq	32(%rsp),%r13
	movq	8(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r9
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	96(%rsp),%r12

	addq	24(%rsp),%r12
	movq	%rbx,%r13
	addq	%rdi,%r12
	movq	%r9,%r14
	rorq	$23,%r13
	movq	%rcx,%rdi

	xorq	%rbx,%r13
	rorq	$5,%r14
	xorq	%rdx,%rdi

	movq	%r12,24(%rsp)
	xorq	%r9,%r14
	andq	%rbx,%rdi

	rorq	$4,%r13
	addq	%r8,%r12
	xorq	%rdx,%rdi

	rorq	$6,%r14
	xorq	%rbx,%r13
	addq	%rdi,%r12

	movq	%r9,%rdi
	addq	(%rbp),%r12
	xorq	%r9,%r14

	xorq	%r10,%rdi
	rorq	$14,%r13
	movq	%r10,%r8

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r8
	addq	%r12,%rax
	addq	%r12,%r8

	leaq	24(%rbp),%rbp
	movq	40(%rsp),%r13
	movq	16(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r8
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	104(%rsp),%r12

	addq	32(%rsp),%r12
	movq	%rax,%r13
	addq	%r15,%r12
	movq	%r8,%r14
	rorq	$23,%r13
	movq	%rbx,%r15

	xorq	%rax,%r13
	rorq	$5,%r14
	xorq	%rcx,%r15

	movq	%r12,32(%rsp)
	xorq	%r8,%r14
	andq	%rax,%r15

	rorq	$4,%r13
	addq	%rdx,%r12
	xorq	%rcx,%r15

	rorq	$6,%r14
	xorq	%rax,%r13
	addq	%r15,%r12

	movq	%r8,%r15
	addq	(%rbp),%r12
	xorq	%r8,%r14

	xorq	%r9,%r15
	rorq	$14,%r13
	movq	%r9,%rdx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rdx
	addq	%r12,%r11
	addq	%r12,%rdx

	leaq	8(%rbp),%rbp
	movq	48(%rsp),%r13
	movq	24(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rdx
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	112(%rsp),%r12

	addq	40(%rsp),%r12
	movq	%r11,%r13
	addq	%rdi,%r12
	movq	%rdx,%r14
	rorq	$23,%r13
	movq	%rax,%rdi

	xorq	%r11,%r13
	rorq	$5,%r14
	xorq	%rbx,%rdi

	movq	%r12,40(%rsp)
	xorq	%rdx,%r14
	andq	%r11,%rdi

	rorq	$4,%r13
	addq	%rcx,%r12
	xorq	%rbx,%rdi

	rorq	$6,%r14
	xorq	%r11,%r13
	addq	%rdi,%r12

	movq	%rdx,%rdi
	addq	(%rbp),%r12
	xorq	%rdx,%r14

	xorq	%r8,%rdi
	rorq	$14,%r13
	movq	%r8,%rcx

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rcx
	addq	%r12,%r10
	addq	%r12,%rcx

	leaq	24(%rbp),%rbp
	movq	56(%rsp),%r13
	movq	32(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rcx
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	120(%rsp),%r12

	addq	48(%rsp),%r12
	movq	%r10,%r13
	addq	%r15,%r12
	movq	%rcx,%r14
	rorq	$23,%r13
	movq	%r11,%r15

	xorq	%r10,%r13
	rorq	$5,%r14
	xorq	%rax,%r15

	movq	%r12,48(%rsp)
	xorq	%rcx,%r14
	andq	%r10,%r15

	rorq	$4,%r13
	addq	%rbx,%r12
	xorq	%rax,%r15

	rorq	$6,%r14
	xorq	%r10,%r13
	addq	%r15,%r12

	movq	%rcx,%r15
	addq	(%rbp),%r12
	xorq	%rcx,%r14

	xorq	%rdx,%r15
	rorq	$14,%r13
	movq	%rdx,%rbx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rbx
	addq	%r12,%r9
	addq	%r12,%rbx

	leaq	8(%rbp),%rbp
	movq	64(%rsp),%r13
	movq	40(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rbx
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	0(%rsp),%r12

	addq	56(%rsp),%r12
	movq	%r9,%r13
	addq	%rdi,%r12
	movq	%rbx,%r14
	rorq	$23,%r13
	movq	%r10,%rdi

	xorq	%r9,%r13
	rorq	$5,%r14
	xorq	%r11,%rdi

	movq	%r12,56(%rsp)
	xorq	%rbx,%r14
	andq	%r9,%rdi

	rorq	$4,%r13
	addq	%rax,%r12
	xorq	%r11,%rdi

	rorq	$6,%r14
	xorq	%r9,%r13
	addq	%rdi,%r12

	movq	%rbx,%rdi
	addq	(%rbp),%r12
	xorq	%rbx,%r14

	xorq	%rcx,%rdi
	rorq	$14,%r13
	movq	%rcx,%rax

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rax
	addq	%r12,%r8
	addq	%r12,%rax

	leaq	24(%rbp),%rbp
	movq	72(%rsp),%r13
	movq	48(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rax
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	8(%rsp),%r12

	addq	64(%rsp),%r12
	movq	%r8,%r13
	addq	%r15,%r12
	movq	%rax,%r14
	rorq	$23,%r13
	movq	%r9,%r15

	xorq	%r8,%r13
	rorq	$5,%r14
	xorq	%r10,%r15

	movq	%r12,64(%rsp)
	xorq	%rax,%r14
	andq	%r8,%r15

	rorq	$4,%r13
	addq	%r11,%r12
	xorq	%r10,%r15

	rorq	$6,%r14
	xorq	%r8,%r13
	addq	%r15,%r12

	movq	%rax,%r15
	addq	(%rbp),%r12
	xorq	%rax,%r14

	xorq	%rbx,%r15
	rorq	$14,%r13
	movq	%rbx,%r11

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r11
	addq	%r12,%rdx
	addq	%r12,%r11

	leaq	8(%rbp),%rbp
	movq	80(%rsp),%r13
	movq	56(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r11
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	16(%rsp),%r12

	addq	72(%rsp),%r12
	movq	%rdx,%r13
	addq	%rdi,%r12
	movq	%r11,%r14
	rorq	$23,%r13
	movq	%r8,%rdi

	xorq	%rdx,%r13
	rorq	$5,%r14
	xorq	%r9,%rdi

	movq	%r12,72(%rsp)
	xorq	%r11,%r14
	andq	%rdx,%rdi

	rorq	$4,%r13
	addq	%r10,%r12
	xorq	%r9,%rdi

	rorq	$6,%r14
	xorq	%rdx,%r13
	addq	%rdi,%r12

	movq	%r11,%rdi
	addq	(%rbp),%r12
	xorq	%r11,%r14

	xorq	%rax,%rdi
	rorq	$14,%r13
	movq	%rax,%r10

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r10
	addq	%r12,%rcx
	addq	%r12,%r10

	leaq	24(%rbp),%rbp
	movq	88(%rsp),%r13
	movq	64(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r10
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	24(%rsp),%r12

	addq	80(%rsp),%r12
	movq	%rcx,%r13
	addq	%r15,%r12
	movq	%r10,%r14
	rorq	$23,%r13
	movq	%rdx,%r15

	xorq	%rcx,%r13
	rorq	$5,%r14
	xorq	%r8,%r15

	movq	%r12,80(%rsp)
	xorq	%r10,%r14
	andq	%rcx,%r15

	rorq	$4,%r13
	addq	%r9,%r12
	xorq	%r8,%r15

	rorq	$6,%r14
	xorq	%rcx,%r13
	addq	%r15,%r12

	movq	%r10,%r15
	addq	(%rbp),%r12
	xorq	%r10,%r14

	xorq	%r11,%r15
	rorq	$14,%r13
	movq	%r11,%r9

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%r9
	addq	%r12,%rbx
	addq	%r12,%r9

	leaq	8(%rbp),%rbp
	movq	96(%rsp),%r13
	movq	72(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r9
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	32(%rsp),%r12

	addq	88(%rsp),%r12
	movq	%rbx,%r13
	addq	%rdi,%r12
	movq	%r9,%r14
	rorq	$23,%r13
	movq	%rcx,%rdi

	xorq	%rbx,%r13
	rorq	$5,%r14
	xorq	%rdx,%rdi

	movq	%r12,88(%rsp)
	xorq	%r9,%r14
	andq	%rbx,%rdi

	rorq	$4,%r13
	addq	%r8,%r12
	xorq	%rdx,%rdi

	rorq	$6,%r14
	xorq	%rbx,%r13
	addq	%rdi,%r12

	movq	%r9,%rdi
	addq	(%rbp),%r12
	xorq	%r9,%r14

	xorq	%r10,%rdi
	rorq	$14,%r13
	movq	%r10,%r8

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%r8
	addq	%r12,%rax
	addq	%r12,%r8

	leaq	24(%rbp),%rbp
	movq	104(%rsp),%r13
	movq	80(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%r8
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	40(%rsp),%r12

	addq	96(%rsp),%r12
	movq	%rax,%r13
	addq	%r15,%r12
	movq	%r8,%r14
	rorq	$23,%r13
	movq	%rbx,%r15

	xorq	%rax,%r13
	rorq	$5,%r14
	xorq	%rcx,%r15

	movq	%r12,96(%rsp)
	xorq	%r8,%r14
	andq	%rax,%r15

	rorq	$4,%r13
	addq	%rdx,%r12
	xorq	%rcx,%r15

	rorq	$6,%r14
	xorq	%rax,%r13
	addq	%r15,%r12

	movq	%r8,%r15
	addq	(%rbp),%r12
	xorq	%r8,%r14

	xorq	%r9,%r15
	rorq	$14,%r13
	movq	%r9,%rdx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rdx
	addq	%r12,%r11
	addq	%r12,%rdx

	leaq	8(%rbp),%rbp
	movq	112(%rsp),%r13
	movq	88(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rdx
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	48(%rsp),%r12

	addq	104(%rsp),%r12
	movq	%r11,%r13
	addq	%rdi,%r12
	movq	%rdx,%r14
	rorq	$23,%r13
	movq	%rax,%rdi

	xorq	%r11,%r13
	rorq	$5,%r14
	xorq	%rbx,%rdi

	movq	%r12,104(%rsp)
	xorq	%rdx,%r14
	andq	%r11,%rdi

	rorq	$4,%r13
	addq	%rcx,%r12
	xorq	%rbx,%rdi

	rorq	$6,%r14
	xorq	%r11,%r13
	addq	%rdi,%r12

	movq	%rdx,%rdi
	addq	(%rbp),%r12
	xorq	%rdx,%r14

	xorq	%r8,%rdi
	rorq	$14,%r13
	movq	%r8,%rcx

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rcx
	addq	%r12,%r10
	addq	%r12,%rcx

	leaq	24(%rbp),%rbp
	movq	120(%rsp),%r13
	movq	96(%rsp),%r15

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rcx
	movq	%r15,%r14
	rorq	$42,%r15

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%r15
	shrq	$6,%r14

	rorq	$19,%r15
	xorq	%r13,%r12
	xorq	%r14,%r15
	addq	56(%rsp),%r12

	addq	112(%rsp),%r12
	movq	%r10,%r13
	addq	%r15,%r12
	movq	%rcx,%r14
	rorq	$23,%r13
	movq	%r11,%r15

	xorq	%r10,%r13
	rorq	$5,%r14
	xorq	%rax,%r15

	movq	%r12,112(%rsp)
	xorq	%rcx,%r14
	andq	%r10,%r15

	rorq	$4,%r13
	addq	%rbx,%r12
	xorq	%rax,%r15

	rorq	$6,%r14
	xorq	%r10,%r13
	addq	%r15,%r12

	movq	%rcx,%r15
	addq	(%rbp),%r12
	xorq	%rcx,%r14

	xorq	%rdx,%r15
	rorq	$14,%r13
	movq	%rdx,%rbx

	andq	%r15,%rdi
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%rdi,%rbx
	addq	%r12,%r9
	addq	%r12,%rbx

	leaq	8(%rbp),%rbp
	movq	0(%rsp),%r13
	movq	104(%rsp),%rdi

	movq	%r13,%r12
	rorq	$7,%r13
	addq	%r14,%rbx
	movq	%rdi,%r14
	rorq	$42,%rdi

	xorq	%r12,%r13
	shrq	$7,%r12
	rorq	$1,%r13
	xorq	%r14,%rdi
	shrq	$6,%r14

	rorq	$19,%rdi
	xorq	%r13,%r12
	xorq	%r14,%rdi
	addq	64(%rsp),%r12

	addq	120(%rsp),%r12
	movq	%r9,%r13
	addq	%rdi,%r12
	movq	%rbx,%r14
	rorq	$23,%r13
	movq	%r10,%rdi

	xorq	%r9,%r13
	rorq	$5,%r14
	xorq	%r11,%rdi

	movq	%r12,120(%rsp)
	xorq	%rbx,%r14
	andq	%r9,%rdi

	rorq	$4,%r13
	addq	%rax,%r12
	xorq	%r11,%rdi

	rorq	$6,%r14
	xorq	%r9,%r13
	addq	%rdi,%r12

	movq	%rbx,%rdi
	addq	(%rbp),%r12
	xorq	%rbx,%r14

	xorq	%rcx,%rdi
	rorq	$14,%r13
	movq	%rcx,%rax

	andq	%rdi,%r15
	rorq	$28,%r14
	addq	%r13,%r12

	xorq	%r15,%rax
	addq	%r12,%r8
	addq	%r12,%rax

	leaq	24(%rbp),%rbp
	cmpb	$0,7(%rbp)
	jnz	.Lrounds_16_xx

	movq	128+0(%rsp),%rdi
	addq	%r14,%rax
	leaq	128(%rsi),%rsi

	addq	0(%rdi),%rax
	addq	8(%rdi),%rbx
	addq	16(%rdi),%rcx
	addq	24(%rdi),%rdx
	addq	32(%rdi),%r8
	addq	40(%rdi),%r9
	addq	48(%rdi),%r10
	addq	56(%rdi),%r11

	cmpq	128+16(%rsp),%rsi

	movq	%rax,0(%rdi)
	movq	%rbx,8(%rdi)
	movq	%rcx,16(%rdi)
	movq	%rdx,24(%rdi)
	movq	%r8,32(%rdi)
	movq	%r9,40(%rdi)
	movq	%r10,48(%rdi)
	movq	%r11,56(%rdi)
	jb	.Lloop

	movq	152(%rsp),%rsi

	movq	-48(%rsi),%r15

	movq	-40(%rsi),%r14

	movq	-32(%rsi),%r13

	movq	-24(%rsi),%r12

	movq	-16(%rsi),%rbp

	movq	-8(%rsi),%rbx

	leaq	(%rsi),%rsp

.Lepilogue:
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_sha512_block_data_order:
.p2align	6

K512:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817

.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.byte	83,72,65,53,49,50,32,98,108,111,99,107,32,116,114,97,110,115,102,111,114,109,32,102,111,114,32,120,56,54,95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.def	sha512_block_data_order_xop;	.scl 3;	.type 32;	.endef
.p2align	6
sha512_block_data_order_xop:
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_sha512_block_data_order_xop:
	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx


.Lxop_shortcut:
	movq	%rsp,%rax

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	shlq	$4,%rdx
	subq	$256,%rsp
	leaq	(%rsi,%rdx,8),%rdx
	andq	$-64,%rsp
	movq	%rdi,128+0(%rsp)
	movq	%rsi,128+8(%rsp)
	movq	%rdx,128+16(%rsp)
	movq	%rax,152(%rsp)

	movaps	%xmm6,128+32(%rsp)
	movaps	%xmm7,128+48(%rsp)
	movaps	%xmm8,128+64(%rsp)
	movaps	%xmm9,128+80(%rsp)
	movaps	%xmm10,128+96(%rsp)
	movaps	%xmm11,128+112(%rsp)
.Lprologue_xop:

	vzeroupper
	movq	0(%rdi),%rax
	movq	8(%rdi),%rbx
	movq	16(%rdi),%rcx
	movq	24(%rdi),%rdx
	movq	32(%rdi),%r8
	movq	40(%rdi),%r9
	movq	48(%rdi),%r10
	movq	56(%rdi),%r11
	jmp	.Lloop_xop
.p2align	4
.Lloop_xop:
	vmovdqa	K512+1280(%rip),%xmm11
	vmovdqu	0(%rsi),%xmm0
	leaq	K512+128(%rip),%rbp
	vmovdqu	16(%rsi),%xmm1
	vmovdqu	32(%rsi),%xmm2
	vpshufb	%xmm11,%xmm0,%xmm0
	vmovdqu	48(%rsi),%xmm3
	vpshufb	%xmm11,%xmm1,%xmm1
	vmovdqu	64(%rsi),%xmm4
	vpshufb	%xmm11,%xmm2,%xmm2
	vmovdqu	80(%rsi),%xmm5
	vpshufb	%xmm11,%xmm3,%xmm3
	vmovdqu	96(%rsi),%xmm6
	vpshufb	%xmm11,%xmm4,%xmm4
	vmovdqu	112(%rsi),%xmm7
	vpshufb	%xmm11,%xmm5,%xmm5
	vpaddq	-128(%rbp),%xmm0,%xmm8
	vpshufb	%xmm11,%xmm6,%xmm6
	vpaddq	-96(%rbp),%xmm1,%xmm9
	vpshufb	%xmm11,%xmm7,%xmm7
	vpaddq	-64(%rbp),%xmm2,%xmm10
	vpaddq	-32(%rbp),%xmm3,%xmm11
	vmovdqa	%xmm8,0(%rsp)
	vpaddq	0(%rbp),%xmm4,%xmm8
	vmovdqa	%xmm9,16(%rsp)
	vpaddq	32(%rbp),%xmm5,%xmm9
	vmovdqa	%xmm10,32(%rsp)
	vpaddq	64(%rbp),%xmm6,%xmm10
	vmovdqa	%xmm11,48(%rsp)
	vpaddq	96(%rbp),%xmm7,%xmm11
	vmovdqa	%xmm8,64(%rsp)
	movq	%rax,%r14
	vmovdqa	%xmm9,80(%rsp)
	movq	%rbx,%rdi
	vmovdqa	%xmm10,96(%rsp)
	xorq	%rcx,%rdi
	vmovdqa	%xmm11,112(%rsp)
	movq	%r8,%r13
	jmp	.Lxop_00_47

.p2align	4
.Lxop_00_47:
	addq	$256,%rbp
	vpalignr	$8,%xmm0,%xmm1,%xmm8
	rorq	$23,%r13
	movq	%r14,%rax
	vpalignr	$8,%xmm4,%xmm5,%xmm11
	movq	%r9,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%r8,%r13
	xorq	%r10,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%rax,%r14
	vpaddq	%xmm11,%xmm0,%xmm0
	andq	%r8,%r12
	xorq	%r8,%r13
	addq	0(%rsp),%r11
	movq	%rax,%r15
.byte	143,72,120,195,209,7
	xorq	%r10,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%rbx,%r15
	addq	%r12,%r11
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,223,3
	xorq	%rax,%r14
	addq	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rbx,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm7,%xmm10
	addq	%r11,%rdx
	addq	%rdi,%r11
	vpaddq	%xmm8,%xmm0,%xmm0
	movq	%rdx,%r13
	addq	%r11,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%r11
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%r8,%r12
	rorq	$5,%r14
	xorq	%rdx,%r13
	xorq	%r9,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%r11,%r14
	andq	%rdx,%r12
	xorq	%rdx,%r13
	vpaddq	%xmm11,%xmm0,%xmm0
	addq	8(%rsp),%r10
	movq	%r11,%rdi
	xorq	%r9,%r12
	rorq	$6,%r14
	vpaddq	-128(%rbp),%xmm0,%xmm10
	xorq	%rax,%rdi
	addq	%r12,%r10
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r11,%r14
	addq	%r13,%r10
	xorq	%rax,%r15
	rorq	$28,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	vmovdqa	%xmm10,0(%rsp)
	vpalignr	$8,%xmm1,%xmm2,%xmm8
	rorq	$23,%r13
	movq	%r14,%r10
	vpalignr	$8,%xmm5,%xmm6,%xmm11
	movq	%rdx,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%rcx,%r13
	xorq	%r8,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%r10,%r14
	vpaddq	%xmm11,%xmm1,%xmm1
	andq	%rcx,%r12
	xorq	%rcx,%r13
	addq	16(%rsp),%r9
	movq	%r10,%r15
.byte	143,72,120,195,209,7
	xorq	%r8,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%r11,%r15
	addq	%r12,%r9
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,216,3
	xorq	%r10,%r14
	addq	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r11,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm0,%xmm10
	addq	%r9,%rbx
	addq	%rdi,%r9
	vpaddq	%xmm8,%xmm1,%xmm1
	movq	%rbx,%r13
	addq	%r9,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%r9
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%rcx,%r12
	rorq	$5,%r14
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%r9,%r14
	andq	%rbx,%r12
	xorq	%rbx,%r13
	vpaddq	%xmm11,%xmm1,%xmm1
	addq	24(%rsp),%r8
	movq	%r9,%rdi
	xorq	%rdx,%r12
	rorq	$6,%r14
	vpaddq	-96(%rbp),%xmm1,%xmm10
	xorq	%r10,%rdi
	addq	%r12,%r8
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r9,%r14
	addq	%r13,%r8
	xorq	%r10,%r15
	rorq	$28,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	vmovdqa	%xmm10,16(%rsp)
	vpalignr	$8,%xmm2,%xmm3,%xmm8
	rorq	$23,%r13
	movq	%r14,%r8
	vpalignr	$8,%xmm6,%xmm7,%xmm11
	movq	%rbx,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%rax,%r13
	xorq	%rcx,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%r8,%r14
	vpaddq	%xmm11,%xmm2,%xmm2
	andq	%rax,%r12
	xorq	%rax,%r13
	addq	32(%rsp),%rdx
	movq	%r8,%r15
.byte	143,72,120,195,209,7
	xorq	%rcx,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%r9,%r15
	addq	%r12,%rdx
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,217,3
	xorq	%r8,%r14
	addq	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r9,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm1,%xmm10
	addq	%rdx,%r11
	addq	%rdi,%rdx
	vpaddq	%xmm8,%xmm2,%xmm2
	movq	%r11,%r13
	addq	%rdx,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%rdx
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%rax,%r12
	rorq	$5,%r14
	xorq	%r11,%r13
	xorq	%rbx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%rdx,%r14
	andq	%r11,%r12
	xorq	%r11,%r13
	vpaddq	%xmm11,%xmm2,%xmm2
	addq	40(%rsp),%rcx
	movq	%rdx,%rdi
	xorq	%rbx,%r12
	rorq	$6,%r14
	vpaddq	-64(%rbp),%xmm2,%xmm10
	xorq	%r8,%rdi
	addq	%r12,%rcx
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rdx,%r14
	addq	%r13,%rcx
	xorq	%r8,%r15
	rorq	$28,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	vmovdqa	%xmm10,32(%rsp)
	vpalignr	$8,%xmm3,%xmm4,%xmm8
	rorq	$23,%r13
	movq	%r14,%rcx
	vpalignr	$8,%xmm7,%xmm0,%xmm11
	movq	%r11,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%r10,%r13
	xorq	%rax,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%rcx,%r14
	vpaddq	%xmm11,%xmm3,%xmm3
	andq	%r10,%r12
	xorq	%r10,%r13
	addq	48(%rsp),%rbx
	movq	%rcx,%r15
.byte	143,72,120,195,209,7
	xorq	%rax,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%rdx,%r15
	addq	%r12,%rbx
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,218,3
	xorq	%rcx,%r14
	addq	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rdx,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm2,%xmm10
	addq	%rbx,%r9
	addq	%rdi,%rbx
	vpaddq	%xmm8,%xmm3,%xmm3
	movq	%r9,%r13
	addq	%rbx,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%rbx
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%r10,%r12
	rorq	$5,%r14
	xorq	%r9,%r13
	xorq	%r11,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%rbx,%r14
	andq	%r9,%r12
	xorq	%r9,%r13
	vpaddq	%xmm11,%xmm3,%xmm3
	addq	56(%rsp),%rax
	movq	%rbx,%rdi
	xorq	%r11,%r12
	rorq	$6,%r14
	vpaddq	-32(%rbp),%xmm3,%xmm10
	xorq	%rcx,%rdi
	addq	%r12,%rax
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rbx,%r14
	addq	%r13,%rax
	xorq	%rcx,%r15
	rorq	$28,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	vmovdqa	%xmm10,48(%rsp)
	vpalignr	$8,%xmm4,%xmm5,%xmm8
	rorq	$23,%r13
	movq	%r14,%rax
	vpalignr	$8,%xmm0,%xmm1,%xmm11
	movq	%r9,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%r8,%r13
	xorq	%r10,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%rax,%r14
	vpaddq	%xmm11,%xmm4,%xmm4
	andq	%r8,%r12
	xorq	%r8,%r13
	addq	64(%rsp),%r11
	movq	%rax,%r15
.byte	143,72,120,195,209,7
	xorq	%r10,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%rbx,%r15
	addq	%r12,%r11
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,219,3
	xorq	%rax,%r14
	addq	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rbx,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm3,%xmm10
	addq	%r11,%rdx
	addq	%rdi,%r11
	vpaddq	%xmm8,%xmm4,%xmm4
	movq	%rdx,%r13
	addq	%r11,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%r11
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%r8,%r12
	rorq	$5,%r14
	xorq	%rdx,%r13
	xorq	%r9,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%r11,%r14
	andq	%rdx,%r12
	xorq	%rdx,%r13
	vpaddq	%xmm11,%xmm4,%xmm4
	addq	72(%rsp),%r10
	movq	%r11,%rdi
	xorq	%r9,%r12
	rorq	$6,%r14
	vpaddq	0(%rbp),%xmm4,%xmm10
	xorq	%rax,%rdi
	addq	%r12,%r10
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r11,%r14
	addq	%r13,%r10
	xorq	%rax,%r15
	rorq	$28,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	vmovdqa	%xmm10,64(%rsp)
	vpalignr	$8,%xmm5,%xmm6,%xmm8
	rorq	$23,%r13
	movq	%r14,%r10
	vpalignr	$8,%xmm1,%xmm2,%xmm11
	movq	%rdx,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%rcx,%r13
	xorq	%r8,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%r10,%r14
	vpaddq	%xmm11,%xmm5,%xmm5
	andq	%rcx,%r12
	xorq	%rcx,%r13
	addq	80(%rsp),%r9
	movq	%r10,%r15
.byte	143,72,120,195,209,7
	xorq	%r8,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%r11,%r15
	addq	%r12,%r9
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,220,3
	xorq	%r10,%r14
	addq	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r11,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm4,%xmm10
	addq	%r9,%rbx
	addq	%rdi,%r9
	vpaddq	%xmm8,%xmm5,%xmm5
	movq	%rbx,%r13
	addq	%r9,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%r9
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%rcx,%r12
	rorq	$5,%r14
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%r9,%r14
	andq	%rbx,%r12
	xorq	%rbx,%r13
	vpaddq	%xmm11,%xmm5,%xmm5
	addq	88(%rsp),%r8
	movq	%r9,%rdi
	xorq	%rdx,%r12
	rorq	$6,%r14
	vpaddq	32(%rbp),%xmm5,%xmm10
	xorq	%r10,%rdi
	addq	%r12,%r8
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r9,%r14
	addq	%r13,%r8
	xorq	%r10,%r15
	rorq	$28,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	vmovdqa	%xmm10,80(%rsp)
	vpalignr	$8,%xmm6,%xmm7,%xmm8
	rorq	$23,%r13
	movq	%r14,%r8
	vpalignr	$8,%xmm2,%xmm3,%xmm11
	movq	%rbx,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%rax,%r13
	xorq	%rcx,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%r8,%r14
	vpaddq	%xmm11,%xmm6,%xmm6
	andq	%rax,%r12
	xorq	%rax,%r13
	addq	96(%rsp),%rdx
	movq	%r8,%r15
.byte	143,72,120,195,209,7
	xorq	%rcx,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%r9,%r15
	addq	%r12,%rdx
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,221,3
	xorq	%r8,%r14
	addq	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r9,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm5,%xmm10
	addq	%rdx,%r11
	addq	%rdi,%rdx
	vpaddq	%xmm8,%xmm6,%xmm6
	movq	%r11,%r13
	addq	%rdx,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%rdx
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%rax,%r12
	rorq	$5,%r14
	xorq	%r11,%r13
	xorq	%rbx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%rdx,%r14
	andq	%r11,%r12
	xorq	%r11,%r13
	vpaddq	%xmm11,%xmm6,%xmm6
	addq	104(%rsp),%rcx
	movq	%rdx,%rdi
	xorq	%rbx,%r12
	rorq	$6,%r14
	vpaddq	64(%rbp),%xmm6,%xmm10
	xorq	%r8,%rdi
	addq	%r12,%rcx
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rdx,%r14
	addq	%r13,%rcx
	xorq	%r8,%r15
	rorq	$28,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	vmovdqa	%xmm10,96(%rsp)
	vpalignr	$8,%xmm7,%xmm0,%xmm8
	rorq	$23,%r13
	movq	%r14,%rcx
	vpalignr	$8,%xmm3,%xmm4,%xmm11
	movq	%r11,%r12
	rorq	$5,%r14
.byte	143,72,120,195,200,56
	xorq	%r10,%r13
	xorq	%rax,%r12
	vpsrlq	$7,%xmm8,%xmm8
	rorq	$4,%r13
	xorq	%rcx,%r14
	vpaddq	%xmm11,%xmm7,%xmm7
	andq	%r10,%r12
	xorq	%r10,%r13
	addq	112(%rsp),%rbx
	movq	%rcx,%r15
.byte	143,72,120,195,209,7
	xorq	%rax,%r12
	rorq	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xorq	%rdx,%r15
	addq	%r12,%rbx
	rorq	$14,%r13
	andq	%r15,%rdi
.byte	143,104,120,195,222,3
	xorq	%rcx,%r14
	addq	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rdx,%rdi
	rorq	$28,%r14
	vpsrlq	$6,%xmm6,%xmm10
	addq	%rbx,%r9
	addq	%rdi,%rbx
	vpaddq	%xmm8,%xmm7,%xmm7
	movq	%r9,%r13
	addq	%rbx,%r14
.byte	143,72,120,195,203,42
	rorq	$23,%r13
	movq	%r14,%rbx
	vpxor	%xmm10,%xmm11,%xmm11
	movq	%r10,%r12
	rorq	$5,%r14
	xorq	%r9,%r13
	xorq	%r11,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	rorq	$4,%r13
	xorq	%rbx,%r14
	andq	%r9,%r12
	xorq	%r9,%r13
	vpaddq	%xmm11,%xmm7,%xmm7
	addq	120(%rsp),%rax
	movq	%rbx,%rdi
	xorq	%r11,%r12
	rorq	$6,%r14
	vpaddq	96(%rbp),%xmm7,%xmm10
	xorq	%rcx,%rdi
	addq	%r12,%rax
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rbx,%r14
	addq	%r13,%rax
	xorq	%rcx,%r15
	rorq	$28,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	vmovdqa	%xmm10,112(%rsp)
	cmpb	$0,135(%rbp)
	jne	.Lxop_00_47
	rorq	$23,%r13
	movq	%r14,%rax
	movq	%r9,%r12
	rorq	$5,%r14
	xorq	%r8,%r13
	xorq	%r10,%r12
	rorq	$4,%r13
	xorq	%rax,%r14
	andq	%r8,%r12
	xorq	%r8,%r13
	addq	0(%rsp),%r11
	movq	%rax,%r15
	xorq	%r10,%r12
	rorq	$6,%r14
	xorq	%rbx,%r15
	addq	%r12,%r11
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%rax,%r14
	addq	%r13,%r11
	xorq	%rbx,%rdi
	rorq	$28,%r14
	addq	%r11,%rdx
	addq	%rdi,%r11
	movq	%rdx,%r13
	addq	%r11,%r14
	rorq	$23,%r13
	movq	%r14,%r11
	movq	%r8,%r12
	rorq	$5,%r14
	xorq	%rdx,%r13
	xorq	%r9,%r12
	rorq	$4,%r13
	xorq	%r11,%r14
	andq	%rdx,%r12
	xorq	%rdx,%r13
	addq	8(%rsp),%r10
	movq	%r11,%rdi
	xorq	%r9,%r12
	rorq	$6,%r14
	xorq	%rax,%rdi
	addq	%r12,%r10
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r11,%r14
	addq	%r13,%r10
	xorq	%rax,%r15
	rorq	$28,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	rorq	$23,%r13
	movq	%r14,%r10
	movq	%rdx,%r12
	rorq	$5,%r14
	xorq	%rcx,%r13
	xorq	%r8,%r12
	rorq	$4,%r13
	xorq	%r10,%r14
	andq	%rcx,%r12
	xorq	%rcx,%r13
	addq	16(%rsp),%r9
	movq	%r10,%r15
	xorq	%r8,%r12
	rorq	$6,%r14
	xorq	%r11,%r15
	addq	%r12,%r9
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%r10,%r14
	addq	%r13,%r9
	xorq	%r11,%rdi
	rorq	$28,%r14
	addq	%r9,%rbx
	addq	%rdi,%r9
	movq	%rbx,%r13
	addq	%r9,%r14
	rorq	$23,%r13
	movq	%r14,%r9
	movq	%rcx,%r12
	rorq	$5,%r14
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	rorq	$4,%r13
	xorq	%r9,%r14
	andq	%rbx,%r12
	xorq	%rbx,%r13
	addq	24(%rsp),%r8
	movq	%r9,%rdi
	xorq	%rdx,%r12
	rorq	$6,%r14
	xorq	%r10,%rdi
	addq	%r12,%r8
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r9,%r14
	addq	%r13,%r8
	xorq	%r10,%r15
	rorq	$28,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	rorq	$23,%r13
	movq	%r14,%r8
	movq	%rbx,%r12
	rorq	$5,%r14
	xorq	%rax,%r13
	xorq	%rcx,%r12
	rorq	$4,%r13
	xorq	%r8,%r14
	andq	%rax,%r12
	xorq	%rax,%r13
	addq	32(%rsp),%rdx
	movq	%r8,%r15
	xorq	%rcx,%r12
	rorq	$6,%r14
	xorq	%r9,%r15
	addq	%r12,%rdx
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%r8,%r14
	addq	%r13,%rdx
	xorq	%r9,%rdi
	rorq	$28,%r14
	addq	%rdx,%r11
	addq	%rdi,%rdx
	movq	%r11,%r13
	addq	%rdx,%r14
	rorq	$23,%r13
	movq	%r14,%rdx
	movq	%rax,%r12
	rorq	$5,%r14
	xorq	%r11,%r13
	xorq	%rbx,%r12
	rorq	$4,%r13
	xorq	%rdx,%r14
	andq	%r11,%r12
	xorq	%r11,%r13
	addq	40(%rsp),%rcx
	movq	%rdx,%rdi
	xorq	%rbx,%r12
	rorq	$6,%r14
	xorq	%r8,%rdi
	addq	%r12,%rcx
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rdx,%r14
	addq	%r13,%rcx
	xorq	%r8,%r15
	rorq	$28,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	rorq	$23,%r13
	movq	%r14,%rcx
	movq	%r11,%r12
	rorq	$5,%r14
	xorq	%r10,%r13
	xorq	%rax,%r12
	rorq	$4,%r13
	xorq	%rcx,%r14
	andq	%r10,%r12
	xorq	%r10,%r13
	addq	48(%rsp),%rbx
	movq	%rcx,%r15
	xorq	%rax,%r12
	rorq	$6,%r14
	xorq	%rdx,%r15
	addq	%r12,%rbx
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%rcx,%r14
	addq	%r13,%rbx
	xorq	%rdx,%rdi
	rorq	$28,%r14
	addq	%rbx,%r9
	addq	%rdi,%rbx
	movq	%r9,%r13
	addq	%rbx,%r14
	rorq	$23,%r13
	movq	%r14,%rbx
	movq	%r10,%r12
	rorq	$5,%r14
	xorq	%r9,%r13
	xorq	%r11,%r12
	rorq	$4,%r13
	xorq	%rbx,%r14
	andq	%r9,%r12
	xorq	%r9,%r13
	addq	56(%rsp),%rax
	movq	%rbx,%rdi
	xorq	%r11,%r12
	rorq	$6,%r14
	xorq	%rcx,%rdi
	addq	%r12,%rax
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rbx,%r14
	addq	%r13,%rax
	xorq	%rcx,%r15
	rorq	$28,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	rorq	$23,%r13
	movq	%r14,%rax
	movq	%r9,%r12
	rorq	$5,%r14
	xorq	%r8,%r13
	xorq	%r10,%r12
	rorq	$4,%r13
	xorq	%rax,%r14
	andq	%r8,%r12
	xorq	%r8,%r13
	addq	64(%rsp),%r11
	movq	%rax,%r15
	xorq	%r10,%r12
	rorq	$6,%r14
	xorq	%rbx,%r15
	addq	%r12,%r11
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%rax,%r14
	addq	%r13,%r11
	xorq	%rbx,%rdi
	rorq	$28,%r14
	addq	%r11,%rdx
	addq	%rdi,%r11
	movq	%rdx,%r13
	addq	%r11,%r14
	rorq	$23,%r13
	movq	%r14,%r11
	movq	%r8,%r12
	rorq	$5,%r14
	xorq	%rdx,%r13
	xorq	%r9,%r12
	rorq	$4,%r13
	xorq	%r11,%r14
	andq	%rdx,%r12
	xorq	%rdx,%r13
	addq	72(%rsp),%r10
	movq	%r11,%rdi
	xorq	%r9,%r12
	rorq	$6,%r14
	xorq	%rax,%rdi
	addq	%r12,%r10
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r11,%r14
	addq	%r13,%r10
	xorq	%rax,%r15
	rorq	$28,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	rorq	$23,%r13
	movq	%r14,%r10
	movq	%rdx,%r12
	rorq	$5,%r14
	xorq	%rcx,%r13
	xorq	%r8,%r12
	rorq	$4,%r13
	xorq	%r10,%r14
	andq	%rcx,%r12
	xorq	%rcx,%r13
	addq	80(%rsp),%r9
	movq	%r10,%r15
	xorq	%r8,%r12
	rorq	$6,%r14
	xorq	%r11,%r15
	addq	%r12,%r9
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%r10,%r14
	addq	%r13,%r9
	xorq	%r11,%rdi
	rorq	$28,%r14
	addq	%r9,%rbx
	addq	%rdi,%r9
	movq	%rbx,%r13
	addq	%r9,%r14
	rorq	$23,%r13
	movq	%r14,%r9
	movq	%rcx,%r12
	rorq	$5,%r14
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	rorq	$4,%r13
	xorq	%r9,%r14
	andq	%rbx,%r12
	xorq	%rbx,%r13
	addq	88(%rsp),%r8
	movq	%r9,%rdi
	xorq	%rdx,%r12
	rorq	$6,%r14
	xorq	%r10,%rdi
	addq	%r12,%r8
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%r9,%r14
	addq	%r13,%r8
	xorq	%r10,%r15
	rorq	$28,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	rorq	$23,%r13
	movq	%r14,%r8
	movq	%rbx,%r12
	rorq	$5,%r14
	xorq	%rax,%r13
	xorq	%rcx,%r12
	rorq	$4,%r13
	xorq	%r8,%r14
	andq	%rax,%r12
	xorq	%rax,%r13
	addq	96(%rsp),%rdx
	movq	%r8,%r15
	xorq	%rcx,%r12
	rorq	$6,%r14
	xorq	%r9,%r15
	addq	%r12,%rdx
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%r8,%r14
	addq	%r13,%rdx
	xorq	%r9,%rdi
	rorq	$28,%r14
	addq	%rdx,%r11
	addq	%rdi,%rdx
	movq	%r11,%r13
	addq	%rdx,%r14
	rorq	$23,%r13
	movq	%r14,%rdx
	movq	%rax,%r12
	rorq	$5,%r14
	xorq	%r11,%r13
	xorq	%rbx,%r12
	rorq	$4,%r13
	xorq	%rdx,%r14
	andq	%r11,%r12
	xorq	%r11,%r13
	addq	104(%rsp),%rcx
	movq	%rdx,%rdi
	xorq	%rbx,%r12
	rorq	$6,%r14
	xorq	%r8,%rdi
	addq	%r12,%rcx
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rdx,%r14
	addq	%r13,%rcx
	xorq	%r8,%r15
	rorq	$28,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	rorq	$23,%r13
	movq	%r14,%rcx
	movq	%r11,%r12
	rorq	$5,%r14
	xorq	%r10,%r13
	xorq	%rax,%r12
	rorq	$4,%r13
	xorq	%rcx,%r14
	andq	%r10,%r12
	xorq	%r10,%r13
	addq	112(%rsp),%rbx
	movq	%rcx,%r15
	xorq	%rax,%r12
	rorq	$6,%r14
	xorq	%rdx,%r15
	addq	%r12,%rbx
	rorq	$14,%r13
	andq	%r15,%rdi
	xorq	%rcx,%r14
	addq	%r13,%rbx
	xorq	%rdx,%rdi
	rorq	$28,%r14
	addq	%rbx,%r9
	addq	%rdi,%rbx
	movq	%r9,%r13
	addq	%rbx,%r14
	rorq	$23,%r13
	movq	%r14,%rbx
	movq	%r10,%r12
	rorq	$5,%r14
	xorq	%r9,%r13
	xorq	%r11,%r12
	rorq	$4,%r13
	xorq	%rbx,%r14
	andq	%r9,%r12
	xorq	%r9,%r13
	addq	120(%rsp),%rax
	movq	%rbx,%rdi
	xorq	%r11,%r12
	rorq	$6,%r14
	xorq	%rcx,%rdi
	addq	%r12,%rax
	rorq	$14,%r13
	andq	%rdi,%r15
	xorq	%rbx,%r14
	addq	%r13,%rax
	xorq	%rcx,%r15
	rorq	$28,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	movq	128+0(%rsp),%rdi
	movq	%r14,%rax

	addq	0(%rdi),%rax
	leaq	128(%rsi),%rsi
	addq	8(%rdi),%rbx
	addq	16(%rdi),%rcx
	addq	24(%rdi),%rdx
	addq	32(%rdi),%r8
	addq	40(%rdi),%r9
	addq	48(%rdi),%r10
	addq	56(%rdi),%r11

	cmpq	128+16(%rsp),%rsi

	movq	%rax,0(%rdi)
	movq	%rbx,8(%rdi)
	movq	%rcx,16(%rdi)
	movq	%rdx,24(%rdi)
	movq	%r8,32(%rdi)
	movq	%r9,40(%rdi)
	movq	%r10,48(%rdi)
	movq	%r11,56(%rdi)
	jb	.Lloop_xop

	movq	152(%rsp),%rsi

	vzeroupper
	movaps	128+32(%rsp),%xmm6
	movaps	128+48(%rsp),%xmm7
	movaps	128+64(%rsp),%xmm8
	movaps	128+80(%rsp),%xmm9
	movaps	128+96(%rsp),%xmm10
	movaps	128+112(%rsp),%xmm11
	movq	-48(%rsi),%r15

	movq	-40(%rsi),%r14

	movq	-32(%rsi),%r13

	movq	-24(%rsi),%r12

	movq	-16(%rsi),%rbp

	movq	-8(%rsi),%rbx

	leaq	(%rsi),%rsp

.Lepilogue_xop:
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_sha512_block_data_order_xop:
.def	sha512_block_data_order_avx;	.scl 3;	.type 32;	.endef
.p2align	6
sha512_block_data_order_avx:
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_sha512_block_data_order_avx:
	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx


.Lavx_shortcut:
	movq	%rsp,%rax

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	shlq	$4,%rdx
	subq	$256,%rsp
	leaq	(%rsi,%rdx,8),%rdx
	andq	$-64,%rsp
	movq	%rdi,128+0(%rsp)
	movq	%rsi,128+8(%rsp)
	movq	%rdx,128+16(%rsp)
	movq	%rax,152(%rsp)

	movaps	%xmm6,128+32(%rsp)
	movaps	%xmm7,128+48(%rsp)
	movaps	%xmm8,128+64(%rsp)
	movaps	%xmm9,128+80(%rsp)
	movaps	%xmm10,128+96(%rsp)
	movaps	%xmm11,128+112(%rsp)
.Lprologue_avx:

	vzeroupper
	movq	0(%rdi),%rax
	movq	8(%rdi),%rbx
	movq	16(%rdi),%rcx
	movq	24(%rdi),%rdx
	movq	32(%rdi),%r8
	movq	40(%rdi),%r9
	movq	48(%rdi),%r10
	movq	56(%rdi),%r11
	jmp	.Lloop_avx
.p2align	4
.Lloop_avx:
	vmovdqa	K512+1280(%rip),%xmm11
	vmovdqu	0(%rsi),%xmm0
	leaq	K512+128(%rip),%rbp
	vmovdqu	16(%rsi),%xmm1
	vmovdqu	32(%rsi),%xmm2
	vpshufb	%xmm11,%xmm0,%xmm0
	vmovdqu	48(%rsi),%xmm3
	vpshufb	%xmm11,%xmm1,%xmm1
	vmovdqu	64(%rsi),%xmm4
	vpshufb	%xmm11,%xmm2,%xmm2
	vmovdqu	80(%rsi),%xmm5
	vpshufb	%xmm11,%xmm3,%xmm3
	vmovdqu	96(%rsi),%xmm6
	vpshufb	%xmm11,%xmm4,%xmm4
	vmovdqu	112(%rsi),%xmm7
	vpshufb	%xmm11,%xmm5,%xmm5
	vpaddq	-128(%rbp),%xmm0,%xmm8
	vpshufb	%xmm11,%xmm6,%xmm6
	vpaddq	-96(%rbp),%xmm1,%xmm9
	vpshufb	%xmm11,%xmm7,%xmm7
	vpaddq	-64(%rbp),%xmm2,%xmm10
	vpaddq	-32(%rbp),%xmm3,%xmm11
	vmovdqa	%xmm8,0(%rsp)
	vpaddq	0(%rbp),%xmm4,%xmm8
	vmovdqa	%xmm9,16(%rsp)
	vpaddq	32(%rbp),%xmm5,%xmm9
	vmovdqa	%xmm10,32(%rsp)
	vpaddq	64(%rbp),%xmm6,%xmm10
	vmovdqa	%xmm11,48(%rsp)
	vpaddq	96(%rbp),%xmm7,%xmm11
	vmovdqa	%xmm8,64(%rsp)
	movq	%rax,%r14
	vmovdqa	%xmm9,80(%rsp)
	movq	%rbx,%rdi
	vmovdqa	%xmm10,96(%rsp)
	xorq	%rcx,%rdi
	vmovdqa	%xmm11,112(%rsp)
	movq	%r8,%r13
	jmp	.Lavx_00_47

.p2align	4
.Lavx_00_47:
	addq	$256,%rbp
	vpalignr	$8,%xmm0,%xmm1,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%rax
	vpalignr	$8,%xmm4,%xmm5,%xmm11
	movq	%r9,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%r8,%r13
	xorq	%r10,%r12
	vpaddq	%xmm11,%xmm0,%xmm0
	shrdq	$4,%r13,%r13
	xorq	%rax,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%r8,%r12
	xorq	%r8,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	0(%rsp),%r11
	movq	%rax,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%r10,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%rbx,%r15
	addq	%r12,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%rax,%r14
	addq	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rbx,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm7,%xmm11
	addq	%r11,%rdx
	addq	%rdi,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%rdx,%r13
	addq	%r11,%r14
	vpsllq	$3,%xmm7,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%r11
	vpaddq	%xmm8,%xmm0,%xmm0
	movq	%r8,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm7,%xmm9
	xorq	%rdx,%r13
	xorq	%r9,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%r11,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%rdx,%r12
	xorq	%rdx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	8(%rsp),%r10
	movq	%r11,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%r9,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%rax,%rdi
	addq	%r12,%r10
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm0,%xmm0
	xorq	%r11,%r14
	addq	%r13,%r10
	vpaddq	-128(%rbp),%xmm0,%xmm10
	xorq	%rax,%r15
	shrdq	$28,%r14,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	vmovdqa	%xmm10,0(%rsp)
	vpalignr	$8,%xmm1,%xmm2,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%r10
	vpalignr	$8,%xmm5,%xmm6,%xmm11
	movq	%rdx,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%rcx,%r13
	xorq	%r8,%r12
	vpaddq	%xmm11,%xmm1,%xmm1
	shrdq	$4,%r13,%r13
	xorq	%r10,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%rcx,%r12
	xorq	%rcx,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	16(%rsp),%r9
	movq	%r10,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%r8,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%r11,%r15
	addq	%r12,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%r10,%r14
	addq	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r11,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm0,%xmm11
	addq	%r9,%rbx
	addq	%rdi,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%rbx,%r13
	addq	%r9,%r14
	vpsllq	$3,%xmm0,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%r9
	vpaddq	%xmm8,%xmm1,%xmm1
	movq	%rcx,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm0,%xmm9
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%r9,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%rbx,%r12
	xorq	%rbx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	24(%rsp),%r8
	movq	%r9,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%rdx,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%r10,%rdi
	addq	%r12,%r8
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm1,%xmm1
	xorq	%r9,%r14
	addq	%r13,%r8
	vpaddq	-96(%rbp),%xmm1,%xmm10
	xorq	%r10,%r15
	shrdq	$28,%r14,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	vmovdqa	%xmm10,16(%rsp)
	vpalignr	$8,%xmm2,%xmm3,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%r8
	vpalignr	$8,%xmm6,%xmm7,%xmm11
	movq	%rbx,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%rax,%r13
	xorq	%rcx,%r12
	vpaddq	%xmm11,%xmm2,%xmm2
	shrdq	$4,%r13,%r13
	xorq	%r8,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%rax,%r12
	xorq	%rax,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	32(%rsp),%rdx
	movq	%r8,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%rcx,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%r9,%r15
	addq	%r12,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%r8,%r14
	addq	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r9,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm1,%xmm11
	addq	%rdx,%r11
	addq	%rdi,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%r11,%r13
	addq	%rdx,%r14
	vpsllq	$3,%xmm1,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%rdx
	vpaddq	%xmm8,%xmm2,%xmm2
	movq	%rax,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm1,%xmm9
	xorq	%r11,%r13
	xorq	%rbx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%rdx,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%r11,%r12
	xorq	%r11,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	40(%rsp),%rcx
	movq	%rdx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%rbx,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%r8,%rdi
	addq	%r12,%rcx
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm2,%xmm2
	xorq	%rdx,%r14
	addq	%r13,%rcx
	vpaddq	-64(%rbp),%xmm2,%xmm10
	xorq	%r8,%r15
	shrdq	$28,%r14,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	vmovdqa	%xmm10,32(%rsp)
	vpalignr	$8,%xmm3,%xmm4,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%rcx
	vpalignr	$8,%xmm7,%xmm0,%xmm11
	movq	%r11,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%r10,%r13
	xorq	%rax,%r12
	vpaddq	%xmm11,%xmm3,%xmm3
	shrdq	$4,%r13,%r13
	xorq	%rcx,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%r10,%r12
	xorq	%r10,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	48(%rsp),%rbx
	movq	%rcx,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%rax,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%rdx,%r15
	addq	%r12,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%rcx,%r14
	addq	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rdx,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm2,%xmm11
	addq	%rbx,%r9
	addq	%rdi,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%r9,%r13
	addq	%rbx,%r14
	vpsllq	$3,%xmm2,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%rbx
	vpaddq	%xmm8,%xmm3,%xmm3
	movq	%r10,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm2,%xmm9
	xorq	%r9,%r13
	xorq	%r11,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%rbx,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%r9,%r12
	xorq	%r9,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	56(%rsp),%rax
	movq	%rbx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%r11,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%rcx,%rdi
	addq	%r12,%rax
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm3,%xmm3
	xorq	%rbx,%r14
	addq	%r13,%rax
	vpaddq	-32(%rbp),%xmm3,%xmm10
	xorq	%rcx,%r15
	shrdq	$28,%r14,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	vmovdqa	%xmm10,48(%rsp)
	vpalignr	$8,%xmm4,%xmm5,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%rax
	vpalignr	$8,%xmm0,%xmm1,%xmm11
	movq	%r9,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%r8,%r13
	xorq	%r10,%r12
	vpaddq	%xmm11,%xmm4,%xmm4
	shrdq	$4,%r13,%r13
	xorq	%rax,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%r8,%r12
	xorq	%r8,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	64(%rsp),%r11
	movq	%rax,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%r10,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%rbx,%r15
	addq	%r12,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%rax,%r14
	addq	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rbx,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm3,%xmm11
	addq	%r11,%rdx
	addq	%rdi,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%rdx,%r13
	addq	%r11,%r14
	vpsllq	$3,%xmm3,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%r11
	vpaddq	%xmm8,%xmm4,%xmm4
	movq	%r8,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm3,%xmm9
	xorq	%rdx,%r13
	xorq	%r9,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%r11,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%rdx,%r12
	xorq	%rdx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	72(%rsp),%r10
	movq	%r11,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%r9,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%rax,%rdi
	addq	%r12,%r10
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm4,%xmm4
	xorq	%r11,%r14
	addq	%r13,%r10
	vpaddq	0(%rbp),%xmm4,%xmm10
	xorq	%rax,%r15
	shrdq	$28,%r14,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	vmovdqa	%xmm10,64(%rsp)
	vpalignr	$8,%xmm5,%xmm6,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%r10
	vpalignr	$8,%xmm1,%xmm2,%xmm11
	movq	%rdx,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%rcx,%r13
	xorq	%r8,%r12
	vpaddq	%xmm11,%xmm5,%xmm5
	shrdq	$4,%r13,%r13
	xorq	%r10,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%rcx,%r12
	xorq	%rcx,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	80(%rsp),%r9
	movq	%r10,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%r8,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%r11,%r15
	addq	%r12,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%r10,%r14
	addq	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r11,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm4,%xmm11
	addq	%r9,%rbx
	addq	%rdi,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%rbx,%r13
	addq	%r9,%r14
	vpsllq	$3,%xmm4,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%r9
	vpaddq	%xmm8,%xmm5,%xmm5
	movq	%rcx,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm4,%xmm9
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%r9,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%rbx,%r12
	xorq	%rbx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	88(%rsp),%r8
	movq	%r9,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%rdx,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%r10,%rdi
	addq	%r12,%r8
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm5,%xmm5
	xorq	%r9,%r14
	addq	%r13,%r8
	vpaddq	32(%rbp),%xmm5,%xmm10
	xorq	%r10,%r15
	shrdq	$28,%r14,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	vmovdqa	%xmm10,80(%rsp)
	vpalignr	$8,%xmm6,%xmm7,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%r8
	vpalignr	$8,%xmm2,%xmm3,%xmm11
	movq	%rbx,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%rax,%r13
	xorq	%rcx,%r12
	vpaddq	%xmm11,%xmm6,%xmm6
	shrdq	$4,%r13,%r13
	xorq	%r8,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%rax,%r12
	xorq	%rax,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	96(%rsp),%rdx
	movq	%r8,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%rcx,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%r9,%r15
	addq	%r12,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%r8,%r14
	addq	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%r9,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm5,%xmm11
	addq	%rdx,%r11
	addq	%rdi,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%r11,%r13
	addq	%rdx,%r14
	vpsllq	$3,%xmm5,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%rdx
	vpaddq	%xmm8,%xmm6,%xmm6
	movq	%rax,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm5,%xmm9
	xorq	%r11,%r13
	xorq	%rbx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%rdx,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%r11,%r12
	xorq	%r11,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	104(%rsp),%rcx
	movq	%rdx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%rbx,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%r8,%rdi
	addq	%r12,%rcx
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm6,%xmm6
	xorq	%rdx,%r14
	addq	%r13,%rcx
	vpaddq	64(%rbp),%xmm6,%xmm10
	xorq	%r8,%r15
	shrdq	$28,%r14,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	vmovdqa	%xmm10,96(%rsp)
	vpalignr	$8,%xmm7,%xmm0,%xmm8
	shrdq	$23,%r13,%r13
	movq	%r14,%rcx
	vpalignr	$8,%xmm3,%xmm4,%xmm11
	movq	%r11,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xorq	%r10,%r13
	xorq	%rax,%r12
	vpaddq	%xmm11,%xmm7,%xmm7
	shrdq	$4,%r13,%r13
	xorq	%rcx,%r14
	vpsrlq	$7,%xmm8,%xmm11
	andq	%r10,%r12
	xorq	%r10,%r13
	vpsllq	$56,%xmm8,%xmm9
	addq	112(%rsp),%rbx
	movq	%rcx,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xorq	%rax,%r12
	shrdq	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xorq	%rdx,%r15
	addq	%r12,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xorq	%rcx,%r14
	addq	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xorq	%rdx,%rdi
	shrdq	$28,%r14,%r14
	vpsrlq	$6,%xmm6,%xmm11
	addq	%rbx,%r9
	addq	%rdi,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	movq	%r9,%r13
	addq	%rbx,%r14
	vpsllq	$3,%xmm6,%xmm10
	shrdq	$23,%r13,%r13
	movq	%r14,%rbx
	vpaddq	%xmm8,%xmm7,%xmm7
	movq	%r10,%r12
	shrdq	$5,%r14,%r14
	vpsrlq	$19,%xmm6,%xmm9
	xorq	%r9,%r13
	xorq	%r11,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrdq	$4,%r13,%r13
	xorq	%rbx,%r14
	vpsllq	$42,%xmm10,%xmm10
	andq	%r9,%r12
	xorq	%r9,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	addq	120(%rsp),%rax
	movq	%rbx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xorq	%r11,%r12
	shrdq	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xorq	%rcx,%rdi
	addq	%r12,%rax
	vpxor	%xmm9,%xmm11,%xmm11
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	vpaddq	%xmm11,%xmm7,%xmm7
	xorq	%rbx,%r14
	addq	%r13,%rax
	vpaddq	96(%rbp),%xmm7,%xmm10
	xorq	%rcx,%r15
	shrdq	$28,%r14,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	vmovdqa	%xmm10,112(%rsp)
	cmpb	$0,135(%rbp)
	jne	.Lavx_00_47
	shrdq	$23,%r13,%r13
	movq	%r14,%rax
	movq	%r9,%r12
	shrdq	$5,%r14,%r14
	xorq	%r8,%r13
	xorq	%r10,%r12
	shrdq	$4,%r13,%r13
	xorq	%rax,%r14
	andq	%r8,%r12
	xorq	%r8,%r13
	addq	0(%rsp),%r11
	movq	%rax,%r15
	xorq	%r10,%r12
	shrdq	$6,%r14,%r14
	xorq	%rbx,%r15
	addq	%r12,%r11
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%rax,%r14
	addq	%r13,%r11
	xorq	%rbx,%rdi
	shrdq	$28,%r14,%r14
	addq	%r11,%rdx
	addq	%rdi,%r11
	movq	%rdx,%r13
	addq	%r11,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r11
	movq	%r8,%r12
	shrdq	$5,%r14,%r14
	xorq	%rdx,%r13
	xorq	%r9,%r12
	shrdq	$4,%r13,%r13
	xorq	%r11,%r14
	andq	%rdx,%r12
	xorq	%rdx,%r13
	addq	8(%rsp),%r10
	movq	%r11,%rdi
	xorq	%r9,%r12
	shrdq	$6,%r14,%r14
	xorq	%rax,%rdi
	addq	%r12,%r10
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%r11,%r14
	addq	%r13,%r10
	xorq	%rax,%r15
	shrdq	$28,%r14,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r10
	movq	%rdx,%r12
	shrdq	$5,%r14,%r14
	xorq	%rcx,%r13
	xorq	%r8,%r12
	shrdq	$4,%r13,%r13
	xorq	%r10,%r14
	andq	%rcx,%r12
	xorq	%rcx,%r13
	addq	16(%rsp),%r9
	movq	%r10,%r15
	xorq	%r8,%r12
	shrdq	$6,%r14,%r14
	xorq	%r11,%r15
	addq	%r12,%r9
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%r10,%r14
	addq	%r13,%r9
	xorq	%r11,%rdi
	shrdq	$28,%r14,%r14
	addq	%r9,%rbx
	addq	%rdi,%r9
	movq	%rbx,%r13
	addq	%r9,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r9
	movq	%rcx,%r12
	shrdq	$5,%r14,%r14
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	shrdq	$4,%r13,%r13
	xorq	%r9,%r14
	andq	%rbx,%r12
	xorq	%rbx,%r13
	addq	24(%rsp),%r8
	movq	%r9,%rdi
	xorq	%rdx,%r12
	shrdq	$6,%r14,%r14
	xorq	%r10,%rdi
	addq	%r12,%r8
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%r9,%r14
	addq	%r13,%r8
	xorq	%r10,%r15
	shrdq	$28,%r14,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r8
	movq	%rbx,%r12
	shrdq	$5,%r14,%r14
	xorq	%rax,%r13
	xorq	%rcx,%r12
	shrdq	$4,%r13,%r13
	xorq	%r8,%r14
	andq	%rax,%r12
	xorq	%rax,%r13
	addq	32(%rsp),%rdx
	movq	%r8,%r15
	xorq	%rcx,%r12
	shrdq	$6,%r14,%r14
	xorq	%r9,%r15
	addq	%r12,%rdx
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%r8,%r14
	addq	%r13,%rdx
	xorq	%r9,%rdi
	shrdq	$28,%r14,%r14
	addq	%rdx,%r11
	addq	%rdi,%rdx
	movq	%r11,%r13
	addq	%rdx,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rdx
	movq	%rax,%r12
	shrdq	$5,%r14,%r14
	xorq	%r11,%r13
	xorq	%rbx,%r12
	shrdq	$4,%r13,%r13
	xorq	%rdx,%r14
	andq	%r11,%r12
	xorq	%r11,%r13
	addq	40(%rsp),%rcx
	movq	%rdx,%rdi
	xorq	%rbx,%r12
	shrdq	$6,%r14,%r14
	xorq	%r8,%rdi
	addq	%r12,%rcx
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%rdx,%r14
	addq	%r13,%rcx
	xorq	%r8,%r15
	shrdq	$28,%r14,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rcx
	movq	%r11,%r12
	shrdq	$5,%r14,%r14
	xorq	%r10,%r13
	xorq	%rax,%r12
	shrdq	$4,%r13,%r13
	xorq	%rcx,%r14
	andq	%r10,%r12
	xorq	%r10,%r13
	addq	48(%rsp),%rbx
	movq	%rcx,%r15
	xorq	%rax,%r12
	shrdq	$6,%r14,%r14
	xorq	%rdx,%r15
	addq	%r12,%rbx
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%rcx,%r14
	addq	%r13,%rbx
	xorq	%rdx,%rdi
	shrdq	$28,%r14,%r14
	addq	%rbx,%r9
	addq	%rdi,%rbx
	movq	%r9,%r13
	addq	%rbx,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rbx
	movq	%r10,%r12
	shrdq	$5,%r14,%r14
	xorq	%r9,%r13
	xorq	%r11,%r12
	shrdq	$4,%r13,%r13
	xorq	%rbx,%r14
	andq	%r9,%r12
	xorq	%r9,%r13
	addq	56(%rsp),%rax
	movq	%rbx,%rdi
	xorq	%r11,%r12
	shrdq	$6,%r14,%r14
	xorq	%rcx,%rdi
	addq	%r12,%rax
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%rbx,%r14
	addq	%r13,%rax
	xorq	%rcx,%r15
	shrdq	$28,%r14,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rax
	movq	%r9,%r12
	shrdq	$5,%r14,%r14
	xorq	%r8,%r13
	xorq	%r10,%r12
	shrdq	$4,%r13,%r13
	xorq	%rax,%r14
	andq	%r8,%r12
	xorq	%r8,%r13
	addq	64(%rsp),%r11
	movq	%rax,%r15
	xorq	%r10,%r12
	shrdq	$6,%r14,%r14
	xorq	%rbx,%r15
	addq	%r12,%r11
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%rax,%r14
	addq	%r13,%r11
	xorq	%rbx,%rdi
	shrdq	$28,%r14,%r14
	addq	%r11,%rdx
	addq	%rdi,%r11
	movq	%rdx,%r13
	addq	%r11,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r11
	movq	%r8,%r12
	shrdq	$5,%r14,%r14
	xorq	%rdx,%r13
	xorq	%r9,%r12
	shrdq	$4,%r13,%r13
	xorq	%r11,%r14
	andq	%rdx,%r12
	xorq	%rdx,%r13
	addq	72(%rsp),%r10
	movq	%r11,%rdi
	xorq	%r9,%r12
	shrdq	$6,%r14,%r14
	xorq	%rax,%rdi
	addq	%r12,%r10
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%r11,%r14
	addq	%r13,%r10
	xorq	%rax,%r15
	shrdq	$28,%r14,%r14
	addq	%r10,%rcx
	addq	%r15,%r10
	movq	%rcx,%r13
	addq	%r10,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r10
	movq	%rdx,%r12
	shrdq	$5,%r14,%r14
	xorq	%rcx,%r13
	xorq	%r8,%r12
	shrdq	$4,%r13,%r13
	xorq	%r10,%r14
	andq	%rcx,%r12
	xorq	%rcx,%r13
	addq	80(%rsp),%r9
	movq	%r10,%r15
	xorq	%r8,%r12
	shrdq	$6,%r14,%r14
	xorq	%r11,%r15
	addq	%r12,%r9
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%r10,%r14
	addq	%r13,%r9
	xorq	%r11,%rdi
	shrdq	$28,%r14,%r14
	addq	%r9,%rbx
	addq	%rdi,%r9
	movq	%rbx,%r13
	addq	%r9,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r9
	movq	%rcx,%r12
	shrdq	$5,%r14,%r14
	xorq	%rbx,%r13
	xorq	%rdx,%r12
	shrdq	$4,%r13,%r13
	xorq	%r9,%r14
	andq	%rbx,%r12
	xorq	%rbx,%r13
	addq	88(%rsp),%r8
	movq	%r9,%rdi
	xorq	%rdx,%r12
	shrdq	$6,%r14,%r14
	xorq	%r10,%rdi
	addq	%r12,%r8
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%r9,%r14
	addq	%r13,%r8
	xorq	%r10,%r15
	shrdq	$28,%r14,%r14
	addq	%r8,%rax
	addq	%r15,%r8
	movq	%rax,%r13
	addq	%r8,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%r8
	movq	%rbx,%r12
	shrdq	$5,%r14,%r14
	xorq	%rax,%r13
	xorq	%rcx,%r12
	shrdq	$4,%r13,%r13
	xorq	%r8,%r14
	andq	%rax,%r12
	xorq	%rax,%r13
	addq	96(%rsp),%rdx
	movq	%r8,%r15
	xorq	%rcx,%r12
	shrdq	$6,%r14,%r14
	xorq	%r9,%r15
	addq	%r12,%rdx
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%r8,%r14
	addq	%r13,%rdx
	xorq	%r9,%rdi
	shrdq	$28,%r14,%r14
	addq	%rdx,%r11
	addq	%rdi,%rdx
	movq	%r11,%r13
	addq	%rdx,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rdx
	movq	%rax,%r12
	shrdq	$5,%r14,%r14
	xorq	%r11,%r13
	xorq	%rbx,%r12
	shrdq	$4,%r13,%r13
	xorq	%rdx,%r14
	andq	%r11,%r12
	xorq	%r11,%r13
	addq	104(%rsp),%rcx
	movq	%rdx,%rdi
	xorq	%rbx,%r12
	shrdq	$6,%r14,%r14
	xorq	%r8,%rdi
	addq	%r12,%rcx
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%rdx,%r14
	addq	%r13,%rcx
	xorq	%r8,%r15
	shrdq	$28,%r14,%r14
	addq	%rcx,%r10
	addq	%r15,%rcx
	movq	%r10,%r13
	addq	%rcx,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rcx
	movq	%r11,%r12
	shrdq	$5,%r14,%r14
	xorq	%r10,%r13
	xorq	%rax,%r12
	shrdq	$4,%r13,%r13
	xorq	%rcx,%r14
	andq	%r10,%r12
	xorq	%r10,%r13
	addq	112(%rsp),%rbx
	movq	%rcx,%r15
	xorq	%rax,%r12
	shrdq	$6,%r14,%r14
	xorq	%rdx,%r15
	addq	%r12,%rbx
	shrdq	$14,%r13,%r13
	andq	%r15,%rdi
	xorq	%rcx,%r14
	addq	%r13,%rbx
	xorq	%rdx,%rdi
	shrdq	$28,%r14,%r14
	addq	%rbx,%r9
	addq	%rdi,%rbx
	movq	%r9,%r13
	addq	%rbx,%r14
	shrdq	$23,%r13,%r13
	movq	%r14,%rbx
	movq	%r10,%r12
	shrdq	$5,%r14,%r14
	xorq	%r9,%r13
	xorq	%r11,%r12
	shrdq	$4,%r13,%r13
	xorq	%rbx,%r14
	andq	%r9,%r12
	xorq	%r9,%r13
	addq	120(%rsp),%rax
	movq	%rbx,%rdi
	xorq	%r11,%r12
	shrdq	$6,%r14,%r14
	xorq	%rcx,%rdi
	addq	%r12,%rax
	shrdq	$14,%r13,%r13
	andq	%rdi,%r15
	xorq	%rbx,%r14
	addq	%r13,%rax
	xorq	%rcx,%r15
	shrdq	$28,%r14,%r14
	addq	%rax,%r8
	addq	%r15,%rax
	movq	%r8,%r13
	addq	%rax,%r14
	movq	128+0(%rsp),%rdi
	movq	%r14,%rax

	addq	0(%rdi),%rax
	leaq	128(%rsi),%rsi
	addq	8(%rdi),%rbx
	addq	16(%rdi),%rcx
	addq	24(%rdi),%rdx
	addq	32(%rdi),%r8
	addq	40(%rdi),%r9
	addq	48(%rdi),%r10
	addq	56(%rdi),%r11

	cmpq	128+16(%rsp),%rsi

	movq	%rax,0(%rdi)
	movq	%rbx,8(%rdi)
	movq	%rcx,16(%rdi)
	movq	%rdx,24(%rdi)
	movq	%r8,32(%rdi)
	movq	%r9,40(%rdi)
	movq	%r10,48(%rdi)
	movq	%r11,56(%rdi)
	jb	.Lloop_avx

	movq	152(%rsp),%rsi

	vzeroupper
	movaps	128+32(%rsp),%xmm6
	movaps	128+48(%rsp),%xmm7
	movaps	128+64(%rsp),%xmm8
	movaps	128+80(%rsp),%xmm9
	movaps	128+96(%rsp),%xmm10
	movaps	128+112(%rsp),%xmm11
	movq	-48(%rsi),%r15

	movq	-40(%rsi),%r14

	movq	-32(%rsi),%r13

	movq	-24(%rsi),%r12

	movq	-16(%rsi),%rbp

	movq	-8(%rsi),%rbx

	leaq	(%rsi),%rsp

.Lepilogue_avx:
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_sha512_block_data_order_avx:
.def	sha512_block_data_order_avx2;	.scl 3;	.type 32;	.endef
.p2align	6
sha512_block_data_order_avx2:
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_sha512_block_data_order_avx2:
	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx


.Lavx2_shortcut:
	movq	%rsp,%rax

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	subq	$1408,%rsp
	shlq	$4,%rdx
	andq	$-2048,%rsp
	leaq	(%rsi,%rdx,8),%rdx
	addq	$1152,%rsp
	movq	%rdi,128+0(%rsp)
	movq	%rsi,128+8(%rsp)
	movq	%rdx,128+16(%rsp)
	movq	%rax,152(%rsp)

	movaps	%xmm6,128+32(%rsp)
	movaps	%xmm7,128+48(%rsp)
	movaps	%xmm8,128+64(%rsp)
	movaps	%xmm9,128+80(%rsp)
	movaps	%xmm10,128+96(%rsp)
	movaps	%xmm11,128+112(%rsp)
.Lprologue_avx2:

	vzeroupper
	subq	$-128,%rsi
	movq	0(%rdi),%rax
	movq	%rsi,%r12
	movq	8(%rdi),%rbx
	cmpq	%rdx,%rsi
	movq	16(%rdi),%rcx
	cmoveq	%rsp,%r12
	movq	24(%rdi),%rdx
	movq	32(%rdi),%r8
	movq	40(%rdi),%r9
	movq	48(%rdi),%r10
	movq	56(%rdi),%r11
	jmp	.Loop_avx2
.p2align	4
.Loop_avx2:
	vmovdqu	-128(%rsi),%xmm0
	vmovdqu	-128+16(%rsi),%xmm1
	vmovdqu	-128+32(%rsi),%xmm2
	leaq	K512+128(%rip),%rbp
	vmovdqu	-128+48(%rsi),%xmm3
	vmovdqu	-128+64(%rsi),%xmm4
	vmovdqu	-128+80(%rsi),%xmm5
	vmovdqu	-128+96(%rsi),%xmm6
	vmovdqu	-128+112(%rsi),%xmm7

	vmovdqa	1152(%rbp),%ymm10
	vinserti128	$1,(%r12),%ymm0,%ymm0
	vinserti128	$1,16(%r12),%ymm1,%ymm1
	vpshufb	%ymm10,%ymm0,%ymm0
	vinserti128	$1,32(%r12),%ymm2,%ymm2
	vpshufb	%ymm10,%ymm1,%ymm1
	vinserti128	$1,48(%r12),%ymm3,%ymm3
	vpshufb	%ymm10,%ymm2,%ymm2
	vinserti128	$1,64(%r12),%ymm4,%ymm4
	vpshufb	%ymm10,%ymm3,%ymm3
	vinserti128	$1,80(%r12),%ymm5,%ymm5
	vpshufb	%ymm10,%ymm4,%ymm4
	vinserti128	$1,96(%r12),%ymm6,%ymm6
	vpshufb	%ymm10,%ymm5,%ymm5
	vinserti128	$1,112(%r12),%ymm7,%ymm7

	vpaddq	-128(%rbp),%ymm0,%ymm8
	vpshufb	%ymm10,%ymm6,%ymm6
	vpaddq	-96(%rbp),%ymm1,%ymm9
	vpshufb	%ymm10,%ymm7,%ymm7
	vpaddq	-64(%rbp),%ymm2,%ymm10
	vpaddq	-32(%rbp),%ymm3,%ymm11
	vmovdqa	%ymm8,0(%rsp)
	vpaddq	0(%rbp),%ymm4,%ymm8
	vmovdqa	%ymm9,32(%rsp)
	vpaddq	32(%rbp),%ymm5,%ymm9
	vmovdqa	%ymm10,64(%rsp)
	vpaddq	64(%rbp),%ymm6,%ymm10
	vmovdqa	%ymm11,96(%rsp)
	leaq	-128(%rsp),%rsp
	vpaddq	96(%rbp),%ymm7,%ymm11
	vmovdqa	%ymm8,0(%rsp)
	xorq	%r14,%r14
	vmovdqa	%ymm9,32(%rsp)
	movq	%rbx,%rdi
	vmovdqa	%ymm10,64(%rsp)
	xorq	%rcx,%rdi
	vmovdqa	%ymm11,96(%rsp)
	movq	%r9,%r12
	addq	$32*8,%rbp
	jmp	.Lavx2_00_47

.p2align	4
.Lavx2_00_47:
	leaq	-128(%rsp),%rsp
	vpalignr	$8,%ymm0,%ymm1,%ymm8
	addq	0+256(%rsp),%r11
	andq	%r8,%r12
	rorxq	$41,%r8,%r13
	vpalignr	$8,%ymm4,%ymm5,%ymm11
	rorxq	$18,%r8,%r15
	leaq	(%rax,%r14,1),%rax
	leaq	(%r11,%r12,1),%r11
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%r10,%r8,%r12
	xorq	%r15,%r13
	rorxq	$14,%r8,%r14
	vpaddq	%ymm11,%ymm0,%ymm0
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%r11,%r12,1),%r11
	xorq	%r14,%r13
	movq	%rax,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%rax,%r12
	leaq	(%r11,%r13,1),%r11
	xorq	%rbx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%rax,%r14
	rorxq	$28,%rax,%r13
	leaq	(%rdx,%r11,1),%rdx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rbx,%rdi
	vpsrlq	$6,%ymm7,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%r11,%rdi,1),%r11
	movq	%r8,%r12
	vpsllq	$3,%ymm7,%ymm10
	vpaddq	%ymm8,%ymm0,%ymm0
	addq	8+256(%rsp),%r10
	andq	%rdx,%r12
	rorxq	$41,%rdx,%r13
	vpsrlq	$19,%ymm7,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%rdx,%rdi
	leaq	(%r11,%r14,1),%r11
	leaq	(%r10,%r12,1),%r10
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%r9,%rdx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rdx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%r10,%r12,1),%r10
	xorq	%r14,%r13
	movq	%r11,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%r11,%r12
	leaq	(%r10,%r13,1),%r10
	xorq	%rax,%rdi
	vpaddq	%ymm11,%ymm0,%ymm0
	rorxq	$34,%r11,%r14
	rorxq	$28,%r11,%r13
	leaq	(%rcx,%r10,1),%rcx
	vpaddq	-128(%rbp),%ymm0,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rax,%r15
	xorq	%r13,%r14
	leaq	(%r10,%r15,1),%r10
	movq	%rdx,%r12
	vmovdqa	%ymm10,0(%rsp)
	vpalignr	$8,%ymm1,%ymm2,%ymm8
	addq	32+256(%rsp),%r9
	andq	%rcx,%r12
	rorxq	$41,%rcx,%r13
	vpalignr	$8,%ymm5,%ymm6,%ymm11
	rorxq	$18,%rcx,%r15
	leaq	(%r10,%r14,1),%r10
	leaq	(%r9,%r12,1),%r9
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%r8,%rcx,%r12
	xorq	%r15,%r13
	rorxq	$14,%rcx,%r14
	vpaddq	%ymm11,%ymm1,%ymm1
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%r9,%r12,1),%r9
	xorq	%r14,%r13
	movq	%r10,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%r10,%r12
	leaq	(%r9,%r13,1),%r9
	xorq	%r11,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%r10,%r14
	rorxq	$28,%r10,%r13
	leaq	(%rbx,%r9,1),%rbx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r11,%rdi
	vpsrlq	$6,%ymm0,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%r9,%rdi,1),%r9
	movq	%rcx,%r12
	vpsllq	$3,%ymm0,%ymm10
	vpaddq	%ymm8,%ymm1,%ymm1
	addq	40+256(%rsp),%r8
	andq	%rbx,%r12
	rorxq	$41,%rbx,%r13
	vpsrlq	$19,%ymm0,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%rbx,%rdi
	leaq	(%r9,%r14,1),%r9
	leaq	(%r8,%r12,1),%r8
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%rdx,%rbx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rbx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%r8,%r12,1),%r8
	xorq	%r14,%r13
	movq	%r9,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%r9,%r12
	leaq	(%r8,%r13,1),%r8
	xorq	%r10,%rdi
	vpaddq	%ymm11,%ymm1,%ymm1
	rorxq	$34,%r9,%r14
	rorxq	$28,%r9,%r13
	leaq	(%rax,%r8,1),%rax
	vpaddq	-96(%rbp),%ymm1,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r10,%r15
	xorq	%r13,%r14
	leaq	(%r8,%r15,1),%r8
	movq	%rbx,%r12
	vmovdqa	%ymm10,32(%rsp)
	vpalignr	$8,%ymm2,%ymm3,%ymm8
	addq	64+256(%rsp),%rdx
	andq	%rax,%r12
	rorxq	$41,%rax,%r13
	vpalignr	$8,%ymm6,%ymm7,%ymm11
	rorxq	$18,%rax,%r15
	leaq	(%r8,%r14,1),%r8
	leaq	(%rdx,%r12,1),%rdx
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%rcx,%rax,%r12
	xorq	%r15,%r13
	rorxq	$14,%rax,%r14
	vpaddq	%ymm11,%ymm2,%ymm2
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%rdx,%r12,1),%rdx
	xorq	%r14,%r13
	movq	%r8,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%r8,%r12
	leaq	(%rdx,%r13,1),%rdx
	xorq	%r9,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%r8,%r14
	rorxq	$28,%r8,%r13
	leaq	(%r11,%rdx,1),%r11
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r9,%rdi
	vpsrlq	$6,%ymm1,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%rdx,%rdi,1),%rdx
	movq	%rax,%r12
	vpsllq	$3,%ymm1,%ymm10
	vpaddq	%ymm8,%ymm2,%ymm2
	addq	72+256(%rsp),%rcx
	andq	%r11,%r12
	rorxq	$41,%r11,%r13
	vpsrlq	$19,%ymm1,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%r11,%rdi
	leaq	(%rdx,%r14,1),%rdx
	leaq	(%rcx,%r12,1),%rcx
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%rbx,%r11,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r11,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%rcx,%r12,1),%rcx
	xorq	%r14,%r13
	movq	%rdx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%rdx,%r12
	leaq	(%rcx,%r13,1),%rcx
	xorq	%r8,%rdi
	vpaddq	%ymm11,%ymm2,%ymm2
	rorxq	$34,%rdx,%r14
	rorxq	$28,%rdx,%r13
	leaq	(%r10,%rcx,1),%r10
	vpaddq	-64(%rbp),%ymm2,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r8,%r15
	xorq	%r13,%r14
	leaq	(%rcx,%r15,1),%rcx
	movq	%r11,%r12
	vmovdqa	%ymm10,64(%rsp)
	vpalignr	$8,%ymm3,%ymm4,%ymm8
	addq	96+256(%rsp),%rbx
	andq	%r10,%r12
	rorxq	$41,%r10,%r13
	vpalignr	$8,%ymm7,%ymm0,%ymm11
	rorxq	$18,%r10,%r15
	leaq	(%rcx,%r14,1),%rcx
	leaq	(%rbx,%r12,1),%rbx
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%rax,%r10,%r12
	xorq	%r15,%r13
	rorxq	$14,%r10,%r14
	vpaddq	%ymm11,%ymm3,%ymm3
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%rbx,%r12,1),%rbx
	xorq	%r14,%r13
	movq	%rcx,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%rcx,%r12
	leaq	(%rbx,%r13,1),%rbx
	xorq	%rdx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%rcx,%r14
	rorxq	$28,%rcx,%r13
	leaq	(%r9,%rbx,1),%r9
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rdx,%rdi
	vpsrlq	$6,%ymm2,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%rbx,%rdi,1),%rbx
	movq	%r10,%r12
	vpsllq	$3,%ymm2,%ymm10
	vpaddq	%ymm8,%ymm3,%ymm3
	addq	104+256(%rsp),%rax
	andq	%r9,%r12
	rorxq	$41,%r9,%r13
	vpsrlq	$19,%ymm2,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%r9,%rdi
	leaq	(%rbx,%r14,1),%rbx
	leaq	(%rax,%r12,1),%rax
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%r11,%r9,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r9,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%rax,%r12,1),%rax
	xorq	%r14,%r13
	movq	%rbx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%rbx,%r12
	leaq	(%rax,%r13,1),%rax
	xorq	%rcx,%rdi
	vpaddq	%ymm11,%ymm3,%ymm3
	rorxq	$34,%rbx,%r14
	rorxq	$28,%rbx,%r13
	leaq	(%r8,%rax,1),%r8
	vpaddq	-32(%rbp),%ymm3,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rcx,%r15
	xorq	%r13,%r14
	leaq	(%rax,%r15,1),%rax
	movq	%r9,%r12
	vmovdqa	%ymm10,96(%rsp)
	leaq	-128(%rsp),%rsp
	vpalignr	$8,%ymm4,%ymm5,%ymm8
	addq	0+256(%rsp),%r11
	andq	%r8,%r12
	rorxq	$41,%r8,%r13
	vpalignr	$8,%ymm0,%ymm1,%ymm11
	rorxq	$18,%r8,%r15
	leaq	(%rax,%r14,1),%rax
	leaq	(%r11,%r12,1),%r11
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%r10,%r8,%r12
	xorq	%r15,%r13
	rorxq	$14,%r8,%r14
	vpaddq	%ymm11,%ymm4,%ymm4
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%r11,%r12,1),%r11
	xorq	%r14,%r13
	movq	%rax,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%rax,%r12
	leaq	(%r11,%r13,1),%r11
	xorq	%rbx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%rax,%r14
	rorxq	$28,%rax,%r13
	leaq	(%rdx,%r11,1),%rdx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rbx,%rdi
	vpsrlq	$6,%ymm3,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%r11,%rdi,1),%r11
	movq	%r8,%r12
	vpsllq	$3,%ymm3,%ymm10
	vpaddq	%ymm8,%ymm4,%ymm4
	addq	8+256(%rsp),%r10
	andq	%rdx,%r12
	rorxq	$41,%rdx,%r13
	vpsrlq	$19,%ymm3,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%rdx,%rdi
	leaq	(%r11,%r14,1),%r11
	leaq	(%r10,%r12,1),%r10
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%r9,%rdx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rdx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%r10,%r12,1),%r10
	xorq	%r14,%r13
	movq	%r11,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%r11,%r12
	leaq	(%r10,%r13,1),%r10
	xorq	%rax,%rdi
	vpaddq	%ymm11,%ymm4,%ymm4
	rorxq	$34,%r11,%r14
	rorxq	$28,%r11,%r13
	leaq	(%rcx,%r10,1),%rcx
	vpaddq	0(%rbp),%ymm4,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rax,%r15
	xorq	%r13,%r14
	leaq	(%r10,%r15,1),%r10
	movq	%rdx,%r12
	vmovdqa	%ymm10,0(%rsp)
	vpalignr	$8,%ymm5,%ymm6,%ymm8
	addq	32+256(%rsp),%r9
	andq	%rcx,%r12
	rorxq	$41,%rcx,%r13
	vpalignr	$8,%ymm1,%ymm2,%ymm11
	rorxq	$18,%rcx,%r15
	leaq	(%r10,%r14,1),%r10
	leaq	(%r9,%r12,1),%r9
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%r8,%rcx,%r12
	xorq	%r15,%r13
	rorxq	$14,%rcx,%r14
	vpaddq	%ymm11,%ymm5,%ymm5
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%r9,%r12,1),%r9
	xorq	%r14,%r13
	movq	%r10,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%r10,%r12
	leaq	(%r9,%r13,1),%r9
	xorq	%r11,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%r10,%r14
	rorxq	$28,%r10,%r13
	leaq	(%rbx,%r9,1),%rbx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r11,%rdi
	vpsrlq	$6,%ymm4,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%r9,%rdi,1),%r9
	movq	%rcx,%r12
	vpsllq	$3,%ymm4,%ymm10
	vpaddq	%ymm8,%ymm5,%ymm5
	addq	40+256(%rsp),%r8
	andq	%rbx,%r12
	rorxq	$41,%rbx,%r13
	vpsrlq	$19,%ymm4,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%rbx,%rdi
	leaq	(%r9,%r14,1),%r9
	leaq	(%r8,%r12,1),%r8
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%rdx,%rbx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rbx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%r8,%r12,1),%r8
	xorq	%r14,%r13
	movq	%r9,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%r9,%r12
	leaq	(%r8,%r13,1),%r8
	xorq	%r10,%rdi
	vpaddq	%ymm11,%ymm5,%ymm5
	rorxq	$34,%r9,%r14
	rorxq	$28,%r9,%r13
	leaq	(%rax,%r8,1),%rax
	vpaddq	32(%rbp),%ymm5,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r10,%r15
	xorq	%r13,%r14
	leaq	(%r8,%r15,1),%r8
	movq	%rbx,%r12
	vmovdqa	%ymm10,32(%rsp)
	vpalignr	$8,%ymm6,%ymm7,%ymm8
	addq	64+256(%rsp),%rdx
	andq	%rax,%r12
	rorxq	$41,%rax,%r13
	vpalignr	$8,%ymm2,%ymm3,%ymm11
	rorxq	$18,%rax,%r15
	leaq	(%r8,%r14,1),%r8
	leaq	(%rdx,%r12,1),%rdx
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%rcx,%rax,%r12
	xorq	%r15,%r13
	rorxq	$14,%rax,%r14
	vpaddq	%ymm11,%ymm6,%ymm6
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%rdx,%r12,1),%rdx
	xorq	%r14,%r13
	movq	%r8,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%r8,%r12
	leaq	(%rdx,%r13,1),%rdx
	xorq	%r9,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%r8,%r14
	rorxq	$28,%r8,%r13
	leaq	(%r11,%rdx,1),%r11
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r9,%rdi
	vpsrlq	$6,%ymm5,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%rdx,%rdi,1),%rdx
	movq	%rax,%r12
	vpsllq	$3,%ymm5,%ymm10
	vpaddq	%ymm8,%ymm6,%ymm6
	addq	72+256(%rsp),%rcx
	andq	%r11,%r12
	rorxq	$41,%r11,%r13
	vpsrlq	$19,%ymm5,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%r11,%rdi
	leaq	(%rdx,%r14,1),%rdx
	leaq	(%rcx,%r12,1),%rcx
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%rbx,%r11,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r11,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%rcx,%r12,1),%rcx
	xorq	%r14,%r13
	movq	%rdx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%rdx,%r12
	leaq	(%rcx,%r13,1),%rcx
	xorq	%r8,%rdi
	vpaddq	%ymm11,%ymm6,%ymm6
	rorxq	$34,%rdx,%r14
	rorxq	$28,%rdx,%r13
	leaq	(%r10,%rcx,1),%r10
	vpaddq	64(%rbp),%ymm6,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r8,%r15
	xorq	%r13,%r14
	leaq	(%rcx,%r15,1),%rcx
	movq	%r11,%r12
	vmovdqa	%ymm10,64(%rsp)
	vpalignr	$8,%ymm7,%ymm0,%ymm8
	addq	96+256(%rsp),%rbx
	andq	%r10,%r12
	rorxq	$41,%r10,%r13
	vpalignr	$8,%ymm3,%ymm4,%ymm11
	rorxq	$18,%r10,%r15
	leaq	(%rcx,%r14,1),%rcx
	leaq	(%rbx,%r12,1),%rbx
	vpsrlq	$1,%ymm8,%ymm10
	andnq	%rax,%r10,%r12
	xorq	%r15,%r13
	rorxq	$14,%r10,%r14
	vpaddq	%ymm11,%ymm7,%ymm7
	vpsrlq	$7,%ymm8,%ymm11
	leaq	(%rbx,%r12,1),%rbx
	xorq	%r14,%r13
	movq	%rcx,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorxq	$39,%rcx,%r12
	leaq	(%rbx,%r13,1),%rbx
	xorq	%rdx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorxq	$34,%rcx,%r14
	rorxq	$28,%rcx,%r13
	leaq	(%r9,%rbx,1),%r9
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rdx,%rdi
	vpsrlq	$6,%ymm6,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xorq	%r13,%r14
	leaq	(%rbx,%rdi,1),%rbx
	movq	%r10,%r12
	vpsllq	$3,%ymm6,%ymm10
	vpaddq	%ymm8,%ymm7,%ymm7
	addq	104+256(%rsp),%rax
	andq	%r9,%r12
	rorxq	$41,%r9,%r13
	vpsrlq	$19,%ymm6,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorxq	$18,%r9,%rdi
	leaq	(%rbx,%r14,1),%rbx
	leaq	(%rax,%r12,1),%rax
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andnq	%r11,%r9,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r9,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	leaq	(%rax,%r12,1),%rax
	xorq	%r14,%r13
	movq	%rbx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorxq	$39,%rbx,%r12
	leaq	(%rax,%r13,1),%rax
	xorq	%rcx,%rdi
	vpaddq	%ymm11,%ymm7,%ymm7
	rorxq	$34,%rbx,%r14
	rorxq	$28,%rbx,%r13
	leaq	(%r8,%rax,1),%r8
	vpaddq	96(%rbp),%ymm7,%ymm10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rcx,%r15
	xorq	%r13,%r14
	leaq	(%rax,%r15,1),%rax
	movq	%r9,%r12
	vmovdqa	%ymm10,96(%rsp)
	leaq	256(%rbp),%rbp
	cmpb	$0,-121(%rbp)
	jne	.Lavx2_00_47
	addq	0+128(%rsp),%r11
	andq	%r8,%r12
	rorxq	$41,%r8,%r13
	rorxq	$18,%r8,%r15
	leaq	(%rax,%r14,1),%rax
	leaq	(%r11,%r12,1),%r11
	andnq	%r10,%r8,%r12
	xorq	%r15,%r13
	rorxq	$14,%r8,%r14
	leaq	(%r11,%r12,1),%r11
	xorq	%r14,%r13
	movq	%rax,%r15
	rorxq	$39,%rax,%r12
	leaq	(%r11,%r13,1),%r11
	xorq	%rbx,%r15
	rorxq	$34,%rax,%r14
	rorxq	$28,%rax,%r13
	leaq	(%rdx,%r11,1),%rdx
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rbx,%rdi
	xorq	%r13,%r14
	leaq	(%r11,%rdi,1),%r11
	movq	%r8,%r12
	addq	8+128(%rsp),%r10
	andq	%rdx,%r12
	rorxq	$41,%rdx,%r13
	rorxq	$18,%rdx,%rdi
	leaq	(%r11,%r14,1),%r11
	leaq	(%r10,%r12,1),%r10
	andnq	%r9,%rdx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rdx,%r14
	leaq	(%r10,%r12,1),%r10
	xorq	%r14,%r13
	movq	%r11,%rdi
	rorxq	$39,%r11,%r12
	leaq	(%r10,%r13,1),%r10
	xorq	%rax,%rdi
	rorxq	$34,%r11,%r14
	rorxq	$28,%r11,%r13
	leaq	(%rcx,%r10,1),%rcx
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rax,%r15
	xorq	%r13,%r14
	leaq	(%r10,%r15,1),%r10
	movq	%rdx,%r12
	addq	32+128(%rsp),%r9
	andq	%rcx,%r12
	rorxq	$41,%rcx,%r13
	rorxq	$18,%rcx,%r15
	leaq	(%r10,%r14,1),%r10
	leaq	(%r9,%r12,1),%r9
	andnq	%r8,%rcx,%r12
	xorq	%r15,%r13
	rorxq	$14,%rcx,%r14
	leaq	(%r9,%r12,1),%r9
	xorq	%r14,%r13
	movq	%r10,%r15
	rorxq	$39,%r10,%r12
	leaq	(%r9,%r13,1),%r9
	xorq	%r11,%r15
	rorxq	$34,%r10,%r14
	rorxq	$28,%r10,%r13
	leaq	(%rbx,%r9,1),%rbx
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r11,%rdi
	xorq	%r13,%r14
	leaq	(%r9,%rdi,1),%r9
	movq	%rcx,%r12
	addq	40+128(%rsp),%r8
	andq	%rbx,%r12
	rorxq	$41,%rbx,%r13
	rorxq	$18,%rbx,%rdi
	leaq	(%r9,%r14,1),%r9
	leaq	(%r8,%r12,1),%r8
	andnq	%rdx,%rbx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rbx,%r14
	leaq	(%r8,%r12,1),%r8
	xorq	%r14,%r13
	movq	%r9,%rdi
	rorxq	$39,%r9,%r12
	leaq	(%r8,%r13,1),%r8
	xorq	%r10,%rdi
	rorxq	$34,%r9,%r14
	rorxq	$28,%r9,%r13
	leaq	(%rax,%r8,1),%rax
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r10,%r15
	xorq	%r13,%r14
	leaq	(%r8,%r15,1),%r8
	movq	%rbx,%r12
	addq	64+128(%rsp),%rdx
	andq	%rax,%r12
	rorxq	$41,%rax,%r13
	rorxq	$18,%rax,%r15
	leaq	(%r8,%r14,1),%r8
	leaq	(%rdx,%r12,1),%rdx
	andnq	%rcx,%rax,%r12
	xorq	%r15,%r13
	rorxq	$14,%rax,%r14
	leaq	(%rdx,%r12,1),%rdx
	xorq	%r14,%r13
	movq	%r8,%r15
	rorxq	$39,%r8,%r12
	leaq	(%rdx,%r13,1),%rdx
	xorq	%r9,%r15
	rorxq	$34,%r8,%r14
	rorxq	$28,%r8,%r13
	leaq	(%r11,%rdx,1),%r11
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r9,%rdi
	xorq	%r13,%r14
	leaq	(%rdx,%rdi,1),%rdx
	movq	%rax,%r12
	addq	72+128(%rsp),%rcx
	andq	%r11,%r12
	rorxq	$41,%r11,%r13
	rorxq	$18,%r11,%rdi
	leaq	(%rdx,%r14,1),%rdx
	leaq	(%rcx,%r12,1),%rcx
	andnq	%rbx,%r11,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r11,%r14
	leaq	(%rcx,%r12,1),%rcx
	xorq	%r14,%r13
	movq	%rdx,%rdi
	rorxq	$39,%rdx,%r12
	leaq	(%rcx,%r13,1),%rcx
	xorq	%r8,%rdi
	rorxq	$34,%rdx,%r14
	rorxq	$28,%rdx,%r13
	leaq	(%r10,%rcx,1),%r10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r8,%r15
	xorq	%r13,%r14
	leaq	(%rcx,%r15,1),%rcx
	movq	%r11,%r12
	addq	96+128(%rsp),%rbx
	andq	%r10,%r12
	rorxq	$41,%r10,%r13
	rorxq	$18,%r10,%r15
	leaq	(%rcx,%r14,1),%rcx
	leaq	(%rbx,%r12,1),%rbx
	andnq	%rax,%r10,%r12
	xorq	%r15,%r13
	rorxq	$14,%r10,%r14
	leaq	(%rbx,%r12,1),%rbx
	xorq	%r14,%r13
	movq	%rcx,%r15
	rorxq	$39,%rcx,%r12
	leaq	(%rbx,%r13,1),%rbx
	xorq	%rdx,%r15
	rorxq	$34,%rcx,%r14
	rorxq	$28,%rcx,%r13
	leaq	(%r9,%rbx,1),%r9
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rdx,%rdi
	xorq	%r13,%r14
	leaq	(%rbx,%rdi,1),%rbx
	movq	%r10,%r12
	addq	104+128(%rsp),%rax
	andq	%r9,%r12
	rorxq	$41,%r9,%r13
	rorxq	$18,%r9,%rdi
	leaq	(%rbx,%r14,1),%rbx
	leaq	(%rax,%r12,1),%rax
	andnq	%r11,%r9,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r9,%r14
	leaq	(%rax,%r12,1),%rax
	xorq	%r14,%r13
	movq	%rbx,%rdi
	rorxq	$39,%rbx,%r12
	leaq	(%rax,%r13,1),%rax
	xorq	%rcx,%rdi
	rorxq	$34,%rbx,%r14
	rorxq	$28,%rbx,%r13
	leaq	(%r8,%rax,1),%r8
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rcx,%r15
	xorq	%r13,%r14
	leaq	(%rax,%r15,1),%rax
	movq	%r9,%r12
	addq	0(%rsp),%r11
	andq	%r8,%r12
	rorxq	$41,%r8,%r13
	rorxq	$18,%r8,%r15
	leaq	(%rax,%r14,1),%rax
	leaq	(%r11,%r12,1),%r11
	andnq	%r10,%r8,%r12
	xorq	%r15,%r13
	rorxq	$14,%r8,%r14
	leaq	(%r11,%r12,1),%r11
	xorq	%r14,%r13
	movq	%rax,%r15
	rorxq	$39,%rax,%r12
	leaq	(%r11,%r13,1),%r11
	xorq	%rbx,%r15
	rorxq	$34,%rax,%r14
	rorxq	$28,%rax,%r13
	leaq	(%rdx,%r11,1),%rdx
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rbx,%rdi
	xorq	%r13,%r14
	leaq	(%r11,%rdi,1),%r11
	movq	%r8,%r12
	addq	8(%rsp),%r10
	andq	%rdx,%r12
	rorxq	$41,%rdx,%r13
	rorxq	$18,%rdx,%rdi
	leaq	(%r11,%r14,1),%r11
	leaq	(%r10,%r12,1),%r10
	andnq	%r9,%rdx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rdx,%r14
	leaq	(%r10,%r12,1),%r10
	xorq	%r14,%r13
	movq	%r11,%rdi
	rorxq	$39,%r11,%r12
	leaq	(%r10,%r13,1),%r10
	xorq	%rax,%rdi
	rorxq	$34,%r11,%r14
	rorxq	$28,%r11,%r13
	leaq	(%rcx,%r10,1),%rcx
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rax,%r15
	xorq	%r13,%r14
	leaq	(%r10,%r15,1),%r10
	movq	%rdx,%r12
	addq	32(%rsp),%r9
	andq	%rcx,%r12
	rorxq	$41,%rcx,%r13
	rorxq	$18,%rcx,%r15
	leaq	(%r10,%r14,1),%r10
	leaq	(%r9,%r12,1),%r9
	andnq	%r8,%rcx,%r12
	xorq	%r15,%r13
	rorxq	$14,%rcx,%r14
	leaq	(%r9,%r12,1),%r9
	xorq	%r14,%r13
	movq	%r10,%r15
	rorxq	$39,%r10,%r12
	leaq	(%r9,%r13,1),%r9
	xorq	%r11,%r15
	rorxq	$34,%r10,%r14
	rorxq	$28,%r10,%r13
	leaq	(%rbx,%r9,1),%rbx
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r11,%rdi
	xorq	%r13,%r14
	leaq	(%r9,%rdi,1),%r9
	movq	%rcx,%r12
	addq	40(%rsp),%r8
	andq	%rbx,%r12
	rorxq	$41,%rbx,%r13
	rorxq	$18,%rbx,%rdi
	leaq	(%r9,%r14,1),%r9
	leaq	(%r8,%r12,1),%r8
	andnq	%rdx,%rbx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rbx,%r14
	leaq	(%r8,%r12,1),%r8
	xorq	%r14,%r13
	movq	%r9,%rdi
	rorxq	$39,%r9,%r12
	leaq	(%r8,%r13,1),%r8
	xorq	%r10,%rdi
	rorxq	$34,%r9,%r14
	rorxq	$28,%r9,%r13
	leaq	(%rax,%r8,1),%rax
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r10,%r15
	xorq	%r13,%r14
	leaq	(%r8,%r15,1),%r8
	movq	%rbx,%r12
	addq	64(%rsp),%rdx
	andq	%rax,%r12
	rorxq	$41,%rax,%r13
	rorxq	$18,%rax,%r15
	leaq	(%r8,%r14,1),%r8
	leaq	(%rdx,%r12,1),%rdx
	andnq	%rcx,%rax,%r12
	xorq	%r15,%r13
	rorxq	$14,%rax,%r14
	leaq	(%rdx,%r12,1),%rdx
	xorq	%r14,%r13
	movq	%r8,%r15
	rorxq	$39,%r8,%r12
	leaq	(%rdx,%r13,1),%rdx
	xorq	%r9,%r15
	rorxq	$34,%r8,%r14
	rorxq	$28,%r8,%r13
	leaq	(%r11,%rdx,1),%r11
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r9,%rdi
	xorq	%r13,%r14
	leaq	(%rdx,%rdi,1),%rdx
	movq	%rax,%r12
	addq	72(%rsp),%rcx
	andq	%r11,%r12
	rorxq	$41,%r11,%r13
	rorxq	$18,%r11,%rdi
	leaq	(%rdx,%r14,1),%rdx
	leaq	(%rcx,%r12,1),%rcx
	andnq	%rbx,%r11,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r11,%r14
	leaq	(%rcx,%r12,1),%rcx
	xorq	%r14,%r13
	movq	%rdx,%rdi
	rorxq	$39,%rdx,%r12
	leaq	(%rcx,%r13,1),%rcx
	xorq	%r8,%rdi
	rorxq	$34,%rdx,%r14
	rorxq	$28,%rdx,%r13
	leaq	(%r10,%rcx,1),%r10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r8,%r15
	xorq	%r13,%r14
	leaq	(%rcx,%r15,1),%rcx
	movq	%r11,%r12
	addq	96(%rsp),%rbx
	andq	%r10,%r12
	rorxq	$41,%r10,%r13
	rorxq	$18,%r10,%r15
	leaq	(%rcx,%r14,1),%rcx
	leaq	(%rbx,%r12,1),%rbx
	andnq	%rax,%r10,%r12
	xorq	%r15,%r13
	rorxq	$14,%r10,%r14
	leaq	(%rbx,%r12,1),%rbx
	xorq	%r14,%r13
	movq	%rcx,%r15
	rorxq	$39,%rcx,%r12
	leaq	(%rbx,%r13,1),%rbx
	xorq	%rdx,%r15
	rorxq	$34,%rcx,%r14
	rorxq	$28,%rcx,%r13
	leaq	(%r9,%rbx,1),%r9
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rdx,%rdi
	xorq	%r13,%r14
	leaq	(%rbx,%rdi,1),%rbx
	movq	%r10,%r12
	addq	104(%rsp),%rax
	andq	%r9,%r12
	rorxq	$41,%r9,%r13
	rorxq	$18,%r9,%rdi
	leaq	(%rbx,%r14,1),%rbx
	leaq	(%rax,%r12,1),%rax
	andnq	%r11,%r9,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r9,%r14
	leaq	(%rax,%r12,1),%rax
	xorq	%r14,%r13
	movq	%rbx,%rdi
	rorxq	$39,%rbx,%r12
	leaq	(%rax,%r13,1),%rax
	xorq	%rcx,%rdi
	rorxq	$34,%rbx,%r14
	rorxq	$28,%rbx,%r13
	leaq	(%r8,%rax,1),%r8
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rcx,%r15
	xorq	%r13,%r14
	leaq	(%rax,%r15,1),%rax
	movq	%r9,%r12
	movq	1280(%rsp),%rdi
	addq	%r14,%rax

	leaq	1152(%rsp),%rbp

	addq	0(%rdi),%rax
	addq	8(%rdi),%rbx
	addq	16(%rdi),%rcx
	addq	24(%rdi),%rdx
	addq	32(%rdi),%r8
	addq	40(%rdi),%r9
	addq	48(%rdi),%r10
	addq	56(%rdi),%r11

	movq	%rax,0(%rdi)
	movq	%rbx,8(%rdi)
	movq	%rcx,16(%rdi)
	movq	%rdx,24(%rdi)
	movq	%r8,32(%rdi)
	movq	%r9,40(%rdi)
	movq	%r10,48(%rdi)
	movq	%r11,56(%rdi)

	cmpq	144(%rbp),%rsi
	je	.Ldone_avx2

	xorq	%r14,%r14
	movq	%rbx,%rdi
	xorq	%rcx,%rdi
	movq	%r9,%r12
	jmp	.Lower_avx2
.p2align	4
.Lower_avx2:
	addq	0+16(%rbp),%r11
	andq	%r8,%r12
	rorxq	$41,%r8,%r13
	rorxq	$18,%r8,%r15
	leaq	(%rax,%r14,1),%rax
	leaq	(%r11,%r12,1),%r11
	andnq	%r10,%r8,%r12
	xorq	%r15,%r13
	rorxq	$14,%r8,%r14
	leaq	(%r11,%r12,1),%r11
	xorq	%r14,%r13
	movq	%rax,%r15
	rorxq	$39,%rax,%r12
	leaq	(%r11,%r13,1),%r11
	xorq	%rbx,%r15
	rorxq	$34,%rax,%r14
	rorxq	$28,%rax,%r13
	leaq	(%rdx,%r11,1),%rdx
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rbx,%rdi
	xorq	%r13,%r14
	leaq	(%r11,%rdi,1),%r11
	movq	%r8,%r12
	addq	8+16(%rbp),%r10
	andq	%rdx,%r12
	rorxq	$41,%rdx,%r13
	rorxq	$18,%rdx,%rdi
	leaq	(%r11,%r14,1),%r11
	leaq	(%r10,%r12,1),%r10
	andnq	%r9,%rdx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rdx,%r14
	leaq	(%r10,%r12,1),%r10
	xorq	%r14,%r13
	movq	%r11,%rdi
	rorxq	$39,%r11,%r12
	leaq	(%r10,%r13,1),%r10
	xorq	%rax,%rdi
	rorxq	$34,%r11,%r14
	rorxq	$28,%r11,%r13
	leaq	(%rcx,%r10,1),%rcx
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rax,%r15
	xorq	%r13,%r14
	leaq	(%r10,%r15,1),%r10
	movq	%rdx,%r12
	addq	32+16(%rbp),%r9
	andq	%rcx,%r12
	rorxq	$41,%rcx,%r13
	rorxq	$18,%rcx,%r15
	leaq	(%r10,%r14,1),%r10
	leaq	(%r9,%r12,1),%r9
	andnq	%r8,%rcx,%r12
	xorq	%r15,%r13
	rorxq	$14,%rcx,%r14
	leaq	(%r9,%r12,1),%r9
	xorq	%r14,%r13
	movq	%r10,%r15
	rorxq	$39,%r10,%r12
	leaq	(%r9,%r13,1),%r9
	xorq	%r11,%r15
	rorxq	$34,%r10,%r14
	rorxq	$28,%r10,%r13
	leaq	(%rbx,%r9,1),%rbx
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r11,%rdi
	xorq	%r13,%r14
	leaq	(%r9,%rdi,1),%r9
	movq	%rcx,%r12
	addq	40+16(%rbp),%r8
	andq	%rbx,%r12
	rorxq	$41,%rbx,%r13
	rorxq	$18,%rbx,%rdi
	leaq	(%r9,%r14,1),%r9
	leaq	(%r8,%r12,1),%r8
	andnq	%rdx,%rbx,%r12
	xorq	%rdi,%r13
	rorxq	$14,%rbx,%r14
	leaq	(%r8,%r12,1),%r8
	xorq	%r14,%r13
	movq	%r9,%rdi
	rorxq	$39,%r9,%r12
	leaq	(%r8,%r13,1),%r8
	xorq	%r10,%rdi
	rorxq	$34,%r9,%r14
	rorxq	$28,%r9,%r13
	leaq	(%rax,%r8,1),%rax
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r10,%r15
	xorq	%r13,%r14
	leaq	(%r8,%r15,1),%r8
	movq	%rbx,%r12
	addq	64+16(%rbp),%rdx
	andq	%rax,%r12
	rorxq	$41,%rax,%r13
	rorxq	$18,%rax,%r15
	leaq	(%r8,%r14,1),%r8
	leaq	(%rdx,%r12,1),%rdx
	andnq	%rcx,%rax,%r12
	xorq	%r15,%r13
	rorxq	$14,%rax,%r14
	leaq	(%rdx,%r12,1),%rdx
	xorq	%r14,%r13
	movq	%r8,%r15
	rorxq	$39,%r8,%r12
	leaq	(%rdx,%r13,1),%rdx
	xorq	%r9,%r15
	rorxq	$34,%r8,%r14
	rorxq	$28,%r8,%r13
	leaq	(%r11,%rdx,1),%r11
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%r9,%rdi
	xorq	%r13,%r14
	leaq	(%rdx,%rdi,1),%rdx
	movq	%rax,%r12
	addq	72+16(%rbp),%rcx
	andq	%r11,%r12
	rorxq	$41,%r11,%r13
	rorxq	$18,%r11,%rdi
	leaq	(%rdx,%r14,1),%rdx
	leaq	(%rcx,%r12,1),%rcx
	andnq	%rbx,%r11,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r11,%r14
	leaq	(%rcx,%r12,1),%rcx
	xorq	%r14,%r13
	movq	%rdx,%rdi
	rorxq	$39,%rdx,%r12
	leaq	(%rcx,%r13,1),%rcx
	xorq	%r8,%rdi
	rorxq	$34,%rdx,%r14
	rorxq	$28,%rdx,%r13
	leaq	(%r10,%rcx,1),%r10
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%r8,%r15
	xorq	%r13,%r14
	leaq	(%rcx,%r15,1),%rcx
	movq	%r11,%r12
	addq	96+16(%rbp),%rbx
	andq	%r10,%r12
	rorxq	$41,%r10,%r13
	rorxq	$18,%r10,%r15
	leaq	(%rcx,%r14,1),%rcx
	leaq	(%rbx,%r12,1),%rbx
	andnq	%rax,%r10,%r12
	xorq	%r15,%r13
	rorxq	$14,%r10,%r14
	leaq	(%rbx,%r12,1),%rbx
	xorq	%r14,%r13
	movq	%rcx,%r15
	rorxq	$39,%rcx,%r12
	leaq	(%rbx,%r13,1),%rbx
	xorq	%rdx,%r15
	rorxq	$34,%rcx,%r14
	rorxq	$28,%rcx,%r13
	leaq	(%r9,%rbx,1),%r9
	andq	%r15,%rdi
	xorq	%r12,%r14
	xorq	%rdx,%rdi
	xorq	%r13,%r14
	leaq	(%rbx,%rdi,1),%rbx
	movq	%r10,%r12
	addq	104+16(%rbp),%rax
	andq	%r9,%r12
	rorxq	$41,%r9,%r13
	rorxq	$18,%r9,%rdi
	leaq	(%rbx,%r14,1),%rbx
	leaq	(%rax,%r12,1),%rax
	andnq	%r11,%r9,%r12
	xorq	%rdi,%r13
	rorxq	$14,%r9,%r14
	leaq	(%rax,%r12,1),%rax
	xorq	%r14,%r13
	movq	%rbx,%rdi
	rorxq	$39,%rbx,%r12
	leaq	(%rax,%r13,1),%rax
	xorq	%rcx,%rdi
	rorxq	$34,%rbx,%r14
	rorxq	$28,%rbx,%r13
	leaq	(%r8,%rax,1),%r8
	andq	%rdi,%r15
	xorq	%r12,%r14
	xorq	%rcx,%r15
	xorq	%r13,%r14
	leaq	(%rax,%r15,1),%rax
	movq	%r9,%r12
	leaq	-128(%rbp),%rbp
	cmpq	%rsp,%rbp
	jae	.Lower_avx2

	movq	1280(%rsp),%rdi
	addq	%r14,%rax

	leaq	1152(%rsp),%rsp



	addq	0(%rdi),%rax
	addq	8(%rdi),%rbx
	addq	16(%rdi),%rcx
	addq	24(%rdi),%rdx
	addq	32(%rdi),%r8
	addq	40(%rdi),%r9
	leaq	256(%rsi),%rsi
	addq	48(%rdi),%r10
	movq	%rsi,%r12
	addq	56(%rdi),%r11
	cmpq	128+16(%rsp),%rsi

	movq	%rax,0(%rdi)
	cmoveq	%rsp,%r12
	movq	%rbx,8(%rdi)
	movq	%rcx,16(%rdi)
	movq	%rdx,24(%rdi)
	movq	%r8,32(%rdi)
	movq	%r9,40(%rdi)
	movq	%r10,48(%rdi)
	movq	%r11,56(%rdi)

	jbe	.Loop_avx2
	leaq	(%rsp),%rbp




.Ldone_avx2:
	movq	152(%rbp),%rsi

	vzeroupper
	movaps	128+32(%rbp),%xmm6
	movaps	128+48(%rbp),%xmm7
	movaps	128+64(%rbp),%xmm8
	movaps	128+80(%rbp),%xmm9
	movaps	128+96(%rbp),%xmm10
	movaps	128+112(%rbp),%xmm11
	movq	-48(%rsi),%r15

	movq	-40(%rsi),%r14

	movq	-32(%rsi),%r13

	movq	-24(%rsi),%r12

	movq	-16(%rsi),%rbp

	movq	-8(%rsi),%rbx

	leaq	(%rsi),%rsp

.Lepilogue_avx2:
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_sha512_block_data_order_avx2:

.def	se_handler;	.scl 3;	.type 32;	.endef
.p2align	4
se_handler:
	pushq	%rsi
	pushq	%rdi
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushfq
	subq	$64,%rsp

	movq	120(%r8),%rax
	movq	248(%r8),%rbx

	movq	8(%r9),%rsi
	movq	56(%r9),%r11

	movl	0(%r11),%r10d
	leaq	(%rsi,%r10,1),%r10
	cmpq	%r10,%rbx
	jb	.Lin_prologue

	movq	152(%r8),%rax

	movl	4(%r11),%r10d
	leaq	(%rsi,%r10,1),%r10
	cmpq	%r10,%rbx
	jae	.Lin_prologue
	leaq	.Lavx2_shortcut(%rip),%r10
	cmpq	%r10,%rbx
	jb	.Lnot_in_avx2

	andq	$-2048,%rax
	addq	$1152,%rax
.Lnot_in_avx2:
	movq	%rax,%rsi
	movq	128+24(%rax),%rax

	movq	-8(%rax),%rbx
	movq	-16(%rax),%rbp
	movq	-24(%rax),%r12
	movq	-32(%rax),%r13
	movq	-40(%rax),%r14
	movq	-48(%rax),%r15
	movq	%rbx,144(%r8)
	movq	%rbp,160(%r8)
	movq	%r12,216(%r8)
	movq	%r13,224(%r8)
	movq	%r14,232(%r8)
	movq	%r15,240(%r8)

	leaq	.Lepilogue(%rip),%r10
	cmpq	%r10,%rbx
	jb	.Lin_prologue

	leaq	128+32(%rsi),%rsi
	leaq	512(%r8),%rdi
	movl	$12,%ecx
.long	0xa548f3fc

.Lin_prologue:
	movq	8(%rax),%rdi
	movq	16(%rax),%rsi
	movq	%rax,152(%r8)
	movq	%rsi,168(%r8)
	movq	%rdi,176(%r8)

	movq	40(%r9),%rdi
	movq	%r8,%rsi
	movl	$154,%ecx
.long	0xa548f3fc

	movq	%r9,%rsi
	xorq	%rcx,%rcx
	movq	8(%rsi),%rdx
	movq	0(%rsi),%r8
	movq	16(%rsi),%r9
	movq	40(%rsi),%r10
	leaq	56(%rsi),%r11
	leaq	24(%rsi),%r12
	movq	%r10,32(%rsp)
	movq	%r11,40(%rsp)
	movq	%r12,48(%rsp)
	movq	%rcx,56(%rsp)
	call	*__imp_RtlVirtualUnwind(%rip)

	movl	$1,%eax
	addq	$64,%rsp
	popfq
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	popq	%rdi
	popq	%rsi
	.byte	0xf3,0xc3

.section	.pdata
.p2align	2
.rva	.LSEH_begin_sha512_block_data_order
.rva	.LSEH_end_sha512_block_data_order
.rva	.LSEH_info_sha512_block_data_order
.rva	.LSEH_begin_sha512_block_data_order_xop
.rva	.LSEH_end_sha512_block_data_order_xop
.rva	.LSEH_info_sha512_block_data_order_xop
.rva	.LSEH_begin_sha512_block_data_order_avx
.rva	.LSEH_end_sha512_block_data_order_avx
.rva	.LSEH_info_sha512_block_data_order_avx
.rva	.LSEH_begin_sha512_block_data_order_avx2
.rva	.LSEH_end_sha512_block_data_order_avx2
.rva	.LSEH_info_sha512_block_data_order_avx2
.section	.xdata
.p2align	3
.LSEH_info_sha512_block_data_order:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lprologue,.Lepilogue
.LSEH_info_sha512_block_data_order_xop:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lprologue_xop,.Lepilogue_xop
.LSEH_info_sha512_block_data_order_avx:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lprologue_avx,.Lepilogue_avx
.LSEH_info_sha512_block_data_order_avx2:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lprologue_avx2,.Lepilogue_avx2

