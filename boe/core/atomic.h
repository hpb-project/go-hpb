// Last Update:2018-05-23 14:45:37
/**
 * @file atomic.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */
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
