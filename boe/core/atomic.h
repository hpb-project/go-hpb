// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

/*
 * Provice a series of atomic functions.
 */
#ifndef ATOMIC_H
#define ATOMIC_H

#define atomic_fetch_and_add(ptr,value) __sync_fetch_and_add((ptr),(value))
#define atomic_fetch_and_sub(ptr,value) __sync_fetch_and_sub((ptr),(value))
#define atomic_fetch_and_or(ptr,value)  __sync_fetch_and_or((ptr), (value))
#define atomic_fetch_and_and(ptr,value) __sync_fetch_and_and((prt),(value))
#define atomic_fetch_and_xor(ptr,value) __sync_fetch_and_xor((prt),(value))
#define atomic_fetch_and_nand(ptr,value) __sync_fetch_and_nand((prt),(value))


#define atomic_add_and_fetch(ptr,value) __sync_add_and_fetch((ptr),(value))
#define atomic_sub_and_fetch(ptr,value) __sync_sub_and_fetch((ptr),(value))
#define atomic_or_and_fetch(ptr,value)  __sync_or_and_fetch((ptr), (value))
#define atomic_and_and_fetch(ptr,value) __sync_and_and_fetch((prt),(value))
#define atomic_xor_and_fetch(ptr,value) __sync_xor_and_fetch((prt),(value))
#define atomic_nand_and_fetch(ptr,value) __sync_nand_fetch((prt),(value))

#define atomic_compare_and_swap(ptr, oldval, newval) __sync_val_compare_and_swap((ptr),(oldval),(newval))

#endif  /*ATOMIC_H*/
