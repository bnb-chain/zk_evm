// Load a single value from bn254 pairings memory.
%macro mload_bn254_pairing
    // stack: offset
    %mload_current(@SEGMENT_BN_PAIRING)
    // stack: value
%endmacro

%macro mload_bn254_pairing(offset)
    // stack:
    PUSH $offset
    // stack: offset
    %mload_current(@SEGMENT_BN_PAIRING)
    // stack: value
%endmacro

// Store a single value to bn254 pairings memory.
%macro mstore_bn254_pairing
    // stack: offset, value
    %mstore_current(@SEGMENT_BN_PAIRING)
    // stack:
%endmacro

// Build an address on the current context within SEGMENT_BN_PAIRING.
%macro create_bn254_pairing_address
    // stack: offset
    PUSH @SEGMENT_BN_PAIRING
    GET_CONTEXT
    %build_address
    // stack: addr
%endmacro

// Store a single value to bn254 pairings memory.
%macro mstore_bn254_pairing_value(value)
    // stack: offset
    %create_bn254_pairing_address
    PUSH $value
    MSTORE_GENERAL
    // stack:
%endmacro

%macro mstore_bn254_pairing(offset)
    // stack: value
    PUSH $offset
    // stack: offset, value
    %mstore_current(@SEGMENT_BN_PAIRING)
    // stack:
%endmacro

// fp254_2 macros

%macro load_fp254_2
    // stack:       ptr
    %create_bn254_pairing_address
    DUP1
    %add_const(1)
    // stack: addr1, addr
    MLOAD_GENERAL
    // stack:   x1, addr
    SWAP1
    // stack: addr0, x1
    MLOAD_GENERAL
    // stack:   x0, x1
%endmacro 

/// complex conjugate
%macro conj_fp254_2
    // stack: a,  b
    SWAP1 
    PUSH 0
    SUBFP254
    SWAP1
    // stack: a, -b 
%endmacro

%macro scale_fp254_2
    // stack:    c, x, y
    SWAP2
    // stack:    y, x, c 
    DUP3
    // stack: c, y, x, c
    MULFP254
    // stack:   cy, x, c
    SWAP2
    // stack:   c, x, cy
    MULFP254
    // stack:     cx, cy 
%endmacro

%macro eq_fp254_2
    // stack: x, x_, y, y_
    SWAP3
    // stack: y_, x_, y, x
    EQ
    // stack: y_==x_, y, x
    SWAP2
    // stack: x, y, y_==x_
    EQ
    // stack: x==y, y_==x_
    AND
%endmacro

%macro add_fp254_2
    // stack: x, x_, y, y_
    SWAP3
    // stack: y_, x_, y, x
    ADDFP254
    // stack:     z_, y, x
    SWAP2
    // stack:     x, y, z_
    ADDFP254
    // stack:        z, z_
%endmacro

%macro sub_fp254_2
    // stack: x, x_, y, y_
    SWAP3
    // stack: y_, x_, y, x
    SWAP1
    // stack: x_, y_, y, x
    SUBFP254
    // stack:     z_, y, x
    SWAP2
    // stack:     x, y, z_
    SUBFP254
    // stack:        z, z_
%endmacro

/// Given z = x + iy: Fp254_2, return complex conjugate z': Fp254_2
/// where input is represented z.re, z.im and output as z'.im, z'.re
/// cost: 9; note this returns y, x for the output x + yi
%macro i9
    // stack:          a , b
    DUP2
    // stack:      b,  a , b
    DUP2
    // stack:  a , b,  a , b
    PUSH 9
    MULFP254
    // stack: 9a , b,  a , b
    SUBFP254
    // stack: 9a - b,  a , b
    SWAP2 
    // stack:  b , a, 9a - b
    PUSH 9
    MULFP254
    // stack  9b , a, 9a - b
    ADDFP254
    // stack: 9b + a, 9a - b 
%endmacro

%macro mul_fp254_2
    // stack:          a, b, c, d
    DUP4
    DUP3
    MULFP254
    // stack:      bd, a, b, c, d
    DUP4 
    DUP3
    MULFP254
    // stack: ac , bd, a, b, c, d 
    SUBFP254
    // stack: ac - bd, a, b, c, d 
    SWAP4
    // stack: d, a, b, c, ac - bd
    MULFP254
    // stack:   ad, b, c, ac - bd
    SWAP2
    // stack:   c, b, ad, ac - bd
    MULFP254
    // stack:    bc , ad, ac - bd
    ADDFP254
    // stack:    bc + ad, ac - bd
    SWAP1
    // stack:    ac - bd, bc + ad
%endmacro 

// load twisted curve

%macro load_fp254_4
    // stack:                         ptr
    %create_bn254_pairing_address
    DUP1
    %add_const(2)
    // stack:                  addr2, addr
    MLOAD_GENERAL
    // stack:                     x2, addr
    DUP2
    %add_const(1)
    // stack:              addr1, x2, addr
    MLOAD_GENERAL
    // stack:                 x1, x2, addr
    DUP3
    %add_const(3)
    // stack:          addr3, x1, x2, addr
    MLOAD_GENERAL
    // stack:             x3, x1, x2, addr
    SWAP3
    // stack:           addr0, x1, x2, x3
    MLOAD_GENERAL
    // stack:              x0, x1, x2, x3
%endmacro

// fp254_6 macros

%macro load_fp254_6
    // stack:                         ptr
    %create_bn254_pairing_address
    DUP1
    %add_const(4)
    // stack:                   addr4, addr
    MLOAD_GENERAL
    // stack:                     x4, addr
    DUP2
    %add_const(3)
    // stack:               addr3, x4, addr
    MLOAD_GENERAL
    // stack:                 x3, x4, addr
    DUP3
    %add_const(2)
    // stack:           addr2, x3, x4, addr
    MLOAD_GENERAL
    // stack:             x2, x3, x4, addr
    DUP4
    %add_const(1)
    // stack:       addr1, x2, x3, x4, addr
    MLOAD_GENERAL
    // stack:         x1, x2, x3, x4, addr
    DUP5
    %add_const(5)
    // stack:   addr5, x1, x2, x3, x4, addr
    MLOAD_GENERAL
    // stack:     x5, x1, x2, x3, x4, addr
    SWAP5
    // stack:   addr0, x1, x2, x3, x4, x5
    MLOAD_GENERAL
    // stack:     x0, x1, x2, x3, x4, x5
%endmacro

%macro load_fp254_6(ptr)
    // stack:
    PUSH $ptr
    %load_fp254_6
    // stack: x0, x1, x2, x3, x4, x5
%endmacro

%macro store_fp254_6
    // stack:      ptr, x0, x1, x2, x3, x4 , x5
    %create_bn254_pairing_address
    SWAP5
    // stack:       x4, x0, x1, x2, x3, addr, x5
    DUP6
    %add_const(4)
    // stack: addr4, x4, x0, x1, x2, x3, addr, x5
    %swap_mstore
    // stack:           x0, x1, x2, x3, addr, x5
    DUP5
    // stack:     addr0, x0, x1, x2, x3, addr, x5
    %swap_mstore
    // stack:               x1, x2, x3, addr, x5
    DUP4
    %add_const(1)
    // stack:         addr1, x1, x2, x3, addr, x5
    %swap_mstore
    // stack:                   x2, x3, addr, x5
    DUP3
    %add_const(2)
    // stack:             addr2, x2, x3, addr, x5
    %swap_mstore
    // stack:                       x3, addr, x5
    DUP2
    %add_const(3)
    // stack:                 addr3, x3, addr, x5
    %swap_mstore
    // stack:                           addr, x5
    %add_const(5)
    // stack:                          addr5, x5
    %swap_mstore
    // stack:
%endmacro

%macro store_fp254_6_double
    // stack:        ptr, x0, x1, x2, x3, x4, x5
    %create_bn254_pairing_address
    SWAP6
    // stack:         x5, x0, x1, x2, x3, x4, addr
    PUSH 2
    MULFP254
    // stack:       2*x5, x0, x1, x2, x3, x4, addr
    DUP7
    %add_const(5)
    // stack: addr5, 2*x5, x0, x1, x2, x3, x4, addr
    %swap_mstore
    // stack:             x0, x1, x2, x3, x4, addr
    PUSH 2
    MULFP254
    // stack:           2*x0, x1, x2, x3, x4, addr
    DUP6
    // stack:     addr0, 2*x0, x1, x2, x3, x4, addr
    %swap_mstore
    // stack:                 x1, x2, x3, x4, addr
    PUSH 2
    MULFP254
    // stack:               2*x1, x2, x3, x4, addr
    DUP5
    %add_const(1)
    // stack:         addr1, 2*x1, x2, x3, x4, addr
    %swap_mstore
    // stack:                     x2, x3, x4, addr
    PUSH 2
    MULFP254
    // stack:                   2*x2, x3, x4, addr
    DUP4
    %add_const(2)
    // stack:             addr2, 2*x2, x3, x4, addr
    %swap_mstore
    // stack:                         x3, x4, addr
    PUSH 2 
    MULFP254
    // stack:                       2*x3, x4, addr
    DUP3
    %add_const(3)
    // stack:                 addr3, 2*x3, x4, addr
    %swap_mstore
    // stack:                             x4, addr
    PUSH 2
    MULFP254
    // stack:                           2*x4, addr
    SWAP1
    // stack:                           addr, 2*x4
    %add_const(4)
    // stack:                          addr4, 2*x4
    %swap_mstore
    // stack:
%endmacro

%macro store_fp254_6(ptr)
    // stack: x0, x1, x2, x3, x4, x5
    PUSH $ptr
    %store_fp254_6
    // stack:
%endmacro

%macro store_fp254_6_sh(ptr)
    // stack:       x0, x1, x2, x3, x4, x5
    PUSH $ptr
    %create_bn254_pairing_address
    // stack: addr, x0, x1, x2, x3, x4, x5
    %add_const(2)
    DUP1
    // stack: addr2, addr2, x0, x1, x2, x3, x4, x5
    SWAP2 MSTORE_GENERAL
    // stack:    addr2, x1, x2, x3, x4, x5
    %add_const(1)
    DUP1
    // stack: addr3, addr3, x1, x2, x3, x4, x5
    SWAP2 MSTORE_GENERAL
    // stack:        addr3, x2, x3, x4, x5
    %add_const(1)
    DUP1
    // stack: addr4, addr4, x2, x3, x4, x5
    SWAP2 MSTORE_GENERAL
    // stack:            addr4, x3, x4, x5
    %add_const(1)
    // stack:            addr5, x3, x4, x5
    %swap_mstore
    // stack:                       x4, x5
    %i9
    // stack:                       y5, y4
    PUSH $ptr  
    %create_bn254_pairing_address
    DUP1
    %add_const(1)
    // stack:          addr1, addr, y5, y4
    SWAP3
    MSTORE_GENERAL
    // stack:                    y5, addr1
    MSTORE_GENERAL
    // stack:
%endmacro

// cost: 2
%macro dup_fp254_2_0
    // stack:       f: 2
    DUP2
    DUP2
    // stack: f: 2, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_2
    // stack:       X: 2, f: 2
    DUP4
    DUP4
    // stack: f: 2, X: 2, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_4
    // stack:       X: 4, f: 2
    DUP6
    DUP6
    // stack: f: 2, X: 4, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_6
    // stack:       X: 6, f: 2
    DUP8
    DUP8
    // stack: f: 2, X: 6, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_7
    // stack:       X: 7, f: 2
    DUP9
    DUP9
    // stack: f: 2, X: 7, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_8
    // stack:       X: 8, f: 2
    DUP10
    DUP10
    // stack: f: 2, X: 8, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_10
    // stack:       X: 10, f: 2
    DUP12
    DUP12
    // stack: f: 2, X: 10, f: 2
%endmacro

// cost: 2
%macro dup_fp254_2_12
    // stack:       X: 12, f: 2
    DUP14
    DUP14
    // stack: f: 2, X: 12, f: 2
%endmacro

// cost: 4
%macro dup_bn_g2
    // stack: X: 2, Y: 2
    %dup_fp254_2_2
    %dup_fp254_2_2
    // stack: X: 2, Y: 2, X: 2, Y: 2
%endmacro

%macro swap_bn_g2
    // stack: P: 4, Q: 4
    %stack (P: 4, Q: 4) -> (Q, P)
    // stack: Q: 4, P: 4
%endmacro

%macro swap_bn_g2_2
    // stack: P: 4, T: 4, Q: 4
    %stack (P: 4, T: 4, Q: 4) -> (Q, T, P)
    // stack: Q: 4, T: 4, P: 4
%endmacro

%macro swap_fp254_2
    // stack:       X: 2, Y: 2
    %stack (x, x_, y, y_) -> (y, y_, x, x_)
    // stack:       Y: 2, X: 2
%endmacro

%macro swap_fp254_2_2
    // stack:       X: 2, T: 2, Y: 2
    %stack (x, x_, t, t_, y, y_) -> (y, y_, t, t_, x, x_)
    // stack:       Y: 2, T: 2, X: 2
%endmacro

%macro swap_fp254_2_4
    // stack:       X: 2, T: 4, Y: 2
    %stack (x, x_, t0, t1, t2, t3, y, y_) -> (y, y_, t0, t1, t2, t3, x, x_)
    // stack:       Y: 2, T: 4, X: 2
%endmacro

// cost: 6
%macro dup_fp254_6_0
    // stack:       f: 6
    DUP6
    DUP6
    DUP6
    DUP6
    DUP6
    DUP6
    // stack: f: 6, f: 6
%endmacro

// cost: 6
%macro dup_fp254_6_2
    // stack:       X: 2, f: 6
    DUP8
    DUP8
    DUP8
    DUP8
    DUP8
    DUP8
    // stack: f: 6, X: 2, f: 6
%endmacro

// cost: 6
%macro dup_fp254_6_6
    // stack:       X: 6, f: 6
    DUP12
    DUP12
    DUP12
    DUP12
    DUP12
    DUP12
    // stack: f: 6, X: 6, f: 6
%endmacro

// cost: 6
%macro dup_fp254_6_7
    // stack:       X: 7, f: 6
    DUP13
    DUP13
    DUP13
    DUP13
    DUP13
    DUP13
    // stack: f: 6, X: 7, f: 6
%endmacro

// cost: 6
%macro dup_fp254_6_8
    // stack:       X: 8, f: 6
    DUP14
    DUP14
    DUP14
    DUP14
    DUP14
    DUP14
    // stack: f: 6, X: 8, f: 6
%endmacro

/// multiply (a + bt + ct^2) by t:
///     t(a + bt + ct^2) = at + bt^2 + ct^3 = (9+i)c + at + bt^2
%macro sh_fp254_6
    // stack:      a, b, c
    %stack (a: 2, b: 2, c: 2) -> (c, a, b)
    // stack:      c, a, b
    %i9
    SWAP1
    // stack: (9+i)c, a, b 
%endmacro

// cost: 16
%macro add_fp254_6
    // stack: f0, f1, f2, f3, f4, f5, g0, g1, g2, g3, g4, g5
    SWAP7
    ADDFP254
    SWAP6
    // stack: f0,     f2, f3, f4, f5, g0, h1, g2, g3, g4, g5 
    SWAP7
    ADDFP254
    SWAP6
    // stack: f0,         f3, f4, f5, g0, h1, h2, g3, g4, g5 
    SWAP7
    ADDFP254
    SWAP6
    // stack: f0,             f4, f5, g0, h1, h2, h3, g4, g5
    SWAP7
    ADDFP254
    SWAP6
    // stack: f0,                 f5, g0, h1, h2, h3, h4, g5
    SWAP7
    ADDFP254
    SWAP6
    // stack: f0,                     g0, h1, h2, h3, h4, h5
    ADDFP254
    // stack:                         h0, h1, h2, h3, h4, h5
%endmacro

// cost: 18
// add two fp254_6 elements with a to-be-popped stack term separating them
//    (f: 6, X, g: 6) -> (f + g)
%macro add_fp254_6_hole
    // stack: f0, f1, f2, f3, f4, f5, X, g0, g1, g2, g3, g4, g5
    SWAP8
    ADDFP254
    SWAP7
    // stack: f0,     f2, f3, f4, f5, X, g0, h1, g2, g3, g4, g5 
    SWAP8
    ADDFP254
    SWAP7
    // stack: f0,         f3, f4, f5, X, g0, h1, h2, g3, g4, g5 
    SWAP8
    ADDFP254
    SWAP7
    // stack: f0,             f4, f5, X, g0, h1, h2, h3, g4, g5
    SWAP8
    ADDFP254
    SWAP7
    // stack: f0,                 f5, X, g0, h1, h2, h3, h4, g5
    SWAP8
    ADDFP254
    SWAP7
    // stack: f0,                     X, g0, h1, h2, h3, h4, h5
    SWAP1
    POP
    ADDFP254
    // stack:                            h0, h1, h2, h3, h4, h5
%endmacro

// *reversed argument subtraction* cost: 17
%macro subr_fp254_6
    // stack: f0, f1, f2, f3, f4, f5, g0, g1, g2, g3, g4, g5
    SWAP7
    SUBFP254
    SWAP6
    // stack: f0,     f2, f3, f4, f5, g0, h1, g2, g3, g4, g5 
    SWAP7
    SUBFP254
    SWAP6
    // stack: f0,         f3, f4, f5, g0, h1, h2, g3, g4, g5 
    SWAP7
    SUBFP254
    SWAP6
    // stack: f0,             f4, f5, g0, h1, h2, h3, g4, g5
    SWAP7
    SUBFP254
    SWAP6
    // stack: f0,                 f5, g0, h1, h2, h3, h4, g5
    SWAP7
    SUBFP254
    SWAP6
    // stack: f0,                     g0, h1, h2, h3, h4, h5
    SWAP1
    SUBFP254
    // stack:                         h0, h1, h2, h3, h4, h5
%endmacro

// cost: 21
%macro scale_re_fp254_6
    // stack: c , f0,      f1,    f2,     f3,     f4,     f5
    SWAP6
    DUP7
    MULFP254
    SWAP6
    // stack: c , f0,      f1,    f2,     f3,     f4, c * f5
    SWAP5
    DUP6
    MULFP254
    SWAP5
    // stack: c , f0,     f1,     f2,     f3, c * f4, c * f5
    SWAP4
    DUP5
    MULFP254
    SWAP4
    // stack: c , f0,     f1,     f2, c * f3, c * f4, c * f5
    SWAP3 
    DUP4 
    MULFP254
    SWAP3 
    // stack: c , f0,     f1, c * f2, c * f3, c *f 4, c * f5
    SWAP2
    DUP3
    MULFP254
    SWAP2
    // stack: c , f0, c * f1, c * f2, c * f3, c * f4, c * f5
    MULFP254
    // stack: c * f0, c * f1, c * f2, c * f3, c * f4, c * f5
%endmacro

/// cost: 
///
/// G0 + G1t + G2t^2 = (a+bi) * (F0 + F1t + F2t^2) 
///                  = (a+bi)F0 + (a+bi)F1t + (a+bi)F2t^2
///
/// G0 = (a+bi)(f0+f0_i) = (af0 - bf0_) + (bf0 + af0_)i
/// G1 = (a+bi)(f1+f1_i) = (af1 - bf1_) + (bf1 + af1_)i
/// G2 = (a+bi)(f2+f2_i) = (af2 - bf2_) + (bf2 + af2_)i

%macro scale_fp254_6
    // stack:             a, b, f0, f0_, f1, f1_, f2, f2_
    DUP2
    DUP5
    MULFP254
    // stack:       bf0_, a, b, f0, f0_, f1, f1_, f2, f2_
    DUP2
    DUP5
    MULFP254
    // stack:  af0, bf0_, a, b, f0, f0_, f1, f1_, f2, f2_
    SUBFP254
    // stack:         g0, a, b, f0, f0_, f1, f1_, f2, f2_
    SWAP3
    // stack:         f0, a, b, g0, f0_, f1, f1_, f2, f2_
    DUP3
    MULFP254
    // stack:        bf0, a, b, g0, f0_, f1, f1_, f2, f2_
    SWAP1
    SWAP4
    // stack:        f0_, bf0, b, g0, a, f1, f1_, f2, f2_
    DUP5
    MULFP254
    // stack:       af0_, bf0, b, g0, a, f1, f1_, f2, f2_
    ADDFP254
    // stack:             g0_, b, g0, a, f1, f1_, f2, f2_
    SWAP3
    // stack:             a, b, g0, g0_, f1, f1_, f2, f2_
    DUP2
    DUP7
    MULFP254
    // stack:       bf1_, a, b, g0, g0_, f1, f1_, f2, f2_
    DUP2
    DUP7
    MULFP254
    // stack:  af1, bf1_, a, b, g0, g0_, f1, f1_, f2, f2_
    SUBFP254
    // stack:         g1, a, b, g0, g0_, f1, f1_, f2, f2_
    SWAP5
    // stack:         f1, a, b, g0, g0_, g1, f1_, f2, f2_
    DUP3
    MULFP254
    // stack:        bf1, a, b, g0, g0_, g1, f1_, f2, f2_
    SWAP1
    SWAP6
    // stack:        f1_, bf1, b, g0, g0_, g1, a, f2, f2_
    DUP7
    MULFP254
    // stack:       af1_, bf1, b, g0, g0_, g1, a, f2, f2_
    ADDFP254
    // stack:             g1_, b, g0, g0_, g1, a, f2, f2_
    SWAP5
    // stack:             a, b, g0, g0_, g1, g1_, f2, f2_
    DUP2
    DUP9
    MULFP254
    // stack:       bf2_, a, b, g0, g0_, g1, g1_, f2, f2_
    DUP2
    DUP9
    MULFP254
    // stack:  af2, bf2_, a, b, g0, g0_, g1, g1_, f2, f2_
    SUBFP254
    // stack:         g2, a, b, g0, g0_, g1, g1_, f2, f2_
    SWAP7
    // stack:         f2, a, b, g0, g0_, g1, g1_, g2, f2_
    SWAP8
    // stack:         f2_, a, b, g0, g0_, g1, g1_, g2, f2
    MULFP254
    // stack:           af2_, b, g0, g0_, g1, g1_, g2, f2
    SWAP7
    // stack:           f2, b, g0, g0_, g1, g1_, g2, af2_
    MULFP254
    // stack:             bf2, g0, g0_, g1, g1_, g2, af2_
    SWAP1
    SWAP6
    // stack:             af2_, bf2, g0_, g1, g1_, g2, g0
    ADDFP254
    // stack:                   g2_, g0_, g1, g1_, g2, g0
    SWAP5
    // stack:                   g0, g0_, g1, g1_, g2, g2_
%endmacro 

/// cost: 1 i9 (9) + 16 dups + 15 swaps + 12 muls + 6 adds/subs = 58
///
/// G0 + G1t + G2t^2 = (a+bi)t * (F0 + F1t + F2t^2) 
///                  = (c+di)F2 + (a+bi)F0t + (a+bi)F1t^2
/// where c+di = (a+bi)(9+i) = (9a-b) + (a+9b)i 
///
/// G0 = (c+di)(f2+f2_i) = (cf2 - df2_) + (df2 + cf2_)i
/// G1 = (a+bi)(f0+f0_i) = (af0 - bf0_) + (bf0 + af0_)i
/// G2 = (a+bi)(f1+f1_i) = (af1 - bf1_) + (bf1 + af1_)i

%macro scale_fp254_6_sh
    // stack:             a, b, f0, f0_, f1, f1_, f2, f2_
    DUP6
    DUP3
    MULFP254
    // stack:       bf1_, a, b, f0, f0_, f1, f1_, f2, f2_
    DUP6 
    DUP3
    MULFP254
    // stack: af1 , bf1_, a, b, f0, f0_, f1, f1_, f2, f2_
    SUBFP254
    // stack:         g2, a, b, f0, f0_, f1, f1_, f2, f2_
    SWAP7
    // stack:         f2, a, b, f0, f0_, f1, f1_, g2, f2_
    SWAP5
    // stack:         f1, a, b, f0, f0_, f2, f1_, g2, f2_
    DUP3
    MULFP254
    // stack:        bf1, a, b, f0, f0_, f2, f1_, g2, f2_
    SWAP1
    SWAP6
    // stack:        f1_, bf1, b, f0, f0_, f2, a, g2, f2_
    DUP7
    MULFP254
    // stack:       af1_, bf1, b, f0, f0_, f2, a, g2, f2_
    ADDFP254
    // stack:             g2_, b, f0, f0_, f2, a, g2, f2_
    SWAP7
    // stack:             f2_, b, f0, f0_, f2, a, g2, g2_
    DUP4
    DUP3
    MULFP254
    // stack:       bf0_, f2_, b, f0, f0_, f2, a, g2, g2_
    DUP4
    DUP8
    MULFP254
    // stack:  af0, bf0_, f2_, b, f0, f0_, f2, a, g2, g2_
    SUBFP254 
    // stack:         g1, f2_, b, f0, f0_, f2, a, g2, g2_
    SWAP5
    // stack:         f2, f2_, b, f0, f0_, g1, a, g2, g2_
    SWAP3
    // stack:         f0, f2_, b, f2, f0_, g1, a, g2, g2_
    DUP3
    MULFP254
    // stack:        bf0, f2_, b, f2, f0_, g1, a, g2, g2_
    SWAP1
    SWAP4
    // stack:        f0_, bf0, b, f2, f2_, g1, a, g2, g2_
    DUP7
    MULFP254
    // stack:       af0_, bf0, b, f2, f2_, g1, a, g2, g2_
    ADDFP254
    // stack:             g1_, b, f2, f2_, g1, a, g2, g2_
    SWAP5 
    // stack:             a, b, f2, f2_, g1, g1_, g2, g2_
    %i9
    // stack:             d, c, f2, f2_, g1, g1_, g2, g2_
    DUP4
    DUP2
    MULFP254
    // stack:       df2_, d, c, f2, f2_, g1, g1_, g2, g2_
    DUP4
    DUP4
    MULFP254
    // stack:  cf2, df2_, d, c, f2, f2_, g1, g1_, g2, g2_
    SUBFP254
    // stack:         g0, d, c, f2, f2_, g1, g1_, g2, g2_
    SWAP3 
    // stack:         f2, d, c, g0, f2_, g1, g1_, g2, g2_
    MULFP254
    // stack:           df2, c, g0, f2_, g1, g1_, g2, g2_
    SWAP3
    MULFP254
    // stack:             cf2_, g0, df2, g1, g1_, g2, g2_
    SWAP1 
    SWAP2
    // stack:             df2, cf2_, g0, g1, g1_, g2, g2_
    ADDFP254
    // stack:                   g0_, g0, g1, g1_, g2, g2_
    SWAP1
    // stack:                   g0, g0_, g1, g1_, g2, g2_
%endmacro

/// cost: 1 i9 (9) + 16 dups + 17 swaps + 12 muls + 6 adds/subs = 60
///
/// G0 + G1t + G2t^2 = (a+bi)t^2 * (F0 + F1t + F2t^2) 
///                  = (c+di)F1 + (c+di)F2t + (a+bi)F0t^2
/// where c+di = (a+bi)(9+i) = (9a-b) + (a+9b)i 
///
/// G0 = (c+di)(f1+f1_i) = (cf1 - df1_) + (df1 + cf1_)i
/// G1 = (a+bi)(f2+f2_i) = (cf2 - df2_) + (df2 + cf2_)i
/// G2 = (a+bi)(f0+f0_i) = (af0 - bf0_) + (bf0 + af0_)i

%macro scale_fp254_6_sh2
    // stack:             a, b, f0, f0_, f1, f1_, f2, f2_
    DUP4
    DUP3 
    MULFP254
    // stack:       bf0_, a, b, f0, f0_, f1, f1_, f2, f2_
    DUP4
    DUP3
    MULFP254
    // stack:  af0, bf0_, a, b, f0, f0_, f1, f1_, f2, f2_
    SUBFP254
    // stack:         g2, a, b, f0, f0_, f1, f1_, f2, f2_
    SWAP7
    SWAP3
    // stack:         f0, a, b, f2, f0_, f1, f1_, g2, f2_
    DUP3
    MULFP254
    // stack:        bf0, a, b, f2, f0_, f1, f1_, g2, f2_
    SWAP1
    SWAP4
    // stack:        f0_, bf0, b, f2, a, f1, f1_, g2, f2_
    DUP5 
    MULFP254
    // stack:       af0_, bf0, b, f2, a, f1, f1_, g2, f2_
    ADDFP254 
    // stack:             g2_, b, f2, a, f1, f1_, g2, f2_
    SWAP7
    SWAP3
    // stack:             a, b, f2, f2_, f1, f1_, g2, g2_
    %i9
    // stack:             d, c, f2, f2_, f1, f1_, g2, g2_
    DUP4
    DUP2
    MULFP254
    // stack:       df2_, d, c, f2, f2_, f1, f1_, g2, g2_
    DUP4
    DUP4
    MULFP254
    // stack:  cf2, df2_, d, c, f2, f2_, f1, f1_, g2, g2_
    SUBFP254
    // stack:         g1, d, c, f2, f2_, f1, f1_, g2, g2_
    SWAP5
    SWAP3
    // stack:         f2, d, c, f1, f2_, g1, f1_, g2, g2_
    DUP2
    MULFP254
    // stack:        df2, d, c, f1, f2_, g1, f1_, g2, g2_
    SWAP1
    SWAP4
    // stack:        f2_, df2, c, f1, d, g1, f1_, g2, g2_
    DUP3
    MULFP254
    // stack:       cf2_, df2, c, f1, d, g1, f1_, g2, g2_
    ADDFP254
    // stack:             g1_, c, f1, d, g1, f1_, g2, g2_
    SWAP5 
    // stack:             f1_, c, f1, d, g1, g1_, g2, g2_
    DUP1
    DUP5 
    MULFP254
    // stack:       df1_, f1_, c, f1, d, g1, g1_, g2, g2_
    DUP4
    DUP4
    MULFP254
    // stack:  cf1, df1_, f1_, c, f1, d, g1, g1_, g2, g2_
    SUBFP254
    // stack:         g0, f1_, c, f1, d, g1, g1_, g2, g2_
    SWAP3
    // stack:         f1, f1_, c, g0, d, g1, g1_, g2, g2_
    SWAP2
    MULFP254
    // stack:           cf1_, f1, g0, d, g1, g1_, g2, g2_
    SWAP3 
    MULFP254
    // stack:             df1, g0, cf1_, g1, g1_, g2, g2_
    SWAP1
    SWAP2
    // stack:             cf1_, df1, g0, g1, g1_, g2, g2_
    ADDFP254
    // stack:                   g0_, g0, g1, g1_, g2, g2_
    SWAP1
    // stack:                   g0, g0_, g1, g1_, g2, g2_
%endmacro

%macro load_fp254_12
    // stack:                                                          ptr
    %create_bn254_pairing_address
    DUP1
    %add_const(10)
    // stack:                                                   addr10, addr
    MLOAD_GENERAL
    // stack:                                                     x10, addr
    DUP2
    %add_const(9)
    // stack:                                              addr09, x10, addr
    MLOAD_GENERAL
    // stack:                                                x09, x10, addr
    DUP3
    %add_const(8)
    // stack:                                         addr08, x09, x10, addr
    MLOAD_GENERAL
    // stack:                                           x08, x09, x10, addr
    DUP4
    %add_const(7)
    // stack:                                    addr07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:                                      x07, x08, x09, x10, addr
    DUP5
    %add_const(6)
    // stack:                               addr06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:                                 x06, x07, x08, x09, x10, addr
    DUP6
    %add_const(5)
    // stack:                          addr05, x06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:                            x05, x06, x07, x08, x09, x10, addr
    DUP7
    %add_const(4)
    // stack:                     addr04, x05, x06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:                       x04, x05, x06, x07, x08, x09, x10, addr
    DUP8
    %add_const(3)
    // stack:                addr03, x04, x05, x06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:                  x03, x04, x05, x06, x07, x08, x09, x10, addr
    DUP9
    %add_const(2)
    // stack:           addr02, x03, x04, x05, x06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:             x02, x03, x04, x05, x06, x07, x08, x09, x10, addr
    DUP10
    %add_const(1)
    // stack:      addr01, x02, x03, x04, x05, x06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:        x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, addr
    DUP11
    %add_const(11)
    // stack: addr11, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, addr
    MLOAD_GENERAL
    // stack:   x11, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, addr
    SWAP11
    // stack: addr00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11
    MLOAD_GENERAL
    // stack:   x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11
%endmacro

%macro store_fp254_12
    // stack:        ptr, x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11
    %create_bn254_pairing_address
    SWAP11
    // stack:        x10, x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    DUP12
    %add_const(10)
    // stack: addr10, x10, x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:             x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    DUP11
    // stack:      addr00, x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                  x01, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    DUP10
    %add_const(01)
    // stack:           addr01, x01, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                       x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    DUP9   
    %add_const(02)
    // stack:                addr02, x02, x03, x04, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                            x03, x04, x05, x06, x07, x08, x09, addr, x11
    DUP8   
    %add_const(03)
    // stack:                     addr03, x03, x04, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                                 x04, x05, x06, x07, x08, x09, addr, x11
    DUP7   
    %add_const(04)
    // stack:                          addr04, x04, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                                      x05, x06, x07, x08, x09, addr, x11
    DUP6   
    %add_const(05)
    // stack:                               addr05, x05, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                                           x06, x07, x08, x09, addr, x11
    DUP5   
    %add_const(06)
    // stack:                                    addr06, x06, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                                                x07, x08, x09, addr, x11
    DUP4   
    %add_const(07)
    // stack:                                         addr07, x07, x08, x09, addr, x11
    %swap_mstore
    // stack:                                                     x08, x09, addr, x11
    DUP3   
    %add_const(08)
    // stack:                                              addr08, x08, x09, addr, x11
    %swap_mstore
    // stack:                                                          x09, addr, x11
    DUP2   
    %add_const(09)
    // stack:                                                   addr09, x09, addr, x11
    %swap_mstore
    // stack:                                                               addr, x11
    %add_const(11)
    // stack:                                                             addr11, x11
    %swap_mstore
    // stack:                                                            
%endmacro

/// moves fp254_12 from src..src+12 to dest..dest+12
/// these should not overlap. leaves scaled DEST on stack
%macro move_fp254_12
    // stack:              src, dest
    PUSH @SEGMENT_BN_PAIRING
    GET_CONTEXT
    %build_address_no_offset
    DUP1
    // stack: base_addr, base_addr, src, dest
    SWAP3 ADD
    // stack: DEST, src, base_addr
    SWAP2 ADD
    // stack:              SRC, DEST
    DUP1
    // stack:       addr00, SRC, DEST
    MLOAD_GENERAL
    // stack:         x00, SRC, DEST
    DUP3
    // stack: addr00', x00, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(1)
    // stack:       addr01, SRC, DEST
    MLOAD_GENERAL
    // stack:         x01, SRC, DEST
    DUP3
    %add_const(1)
    // stack: addr01', x01, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(2)
    // stack:       addr02, SRC, DEST
    MLOAD_GENERAL
    // stack:         x02, SRC, DEST
    DUP3
    %add_const(2)
    // stack: addr02', x02, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(3)
    // stack:       addr03, SRC, DEST
    MLOAD_GENERAL
    // stack:         x03, SRC, DEST
    DUP3
    %add_const(3)
    // stack: addr03', x03, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(4)
    // stack:       addr04, SRC, DEST
    MLOAD_GENERAL
    // stack:         x04, SRC, DEST
    DUP3 
    %add_const(4)
    // stack: addr04', x04, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(5)
    // stack:       addr05, SRC, DEST
    MLOAD_GENERAL
    // stack:         x05, SRC, DEST
    DUP3
    %add_const(5)
    // stack: addr05', x05, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(6)
    // stack:       addr06, SRC, DEST
    MLOAD_GENERAL
    // stack:         x06, SRC, DEST
    DUP3
    %add_const(6)
    // stack: addr06', x06, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(7)
    // stack:       addr07, SRC, DEST
    MLOAD_GENERAL
    // stack:         x07, SRC, DEST
    DUP3
    %add_const(7)
    // stack: addr07', x07, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(8)
    // stack:       addr08, SRC, DEST
    MLOAD_GENERAL
    // stack:         x08, SRC, DEST
    DUP3
    %add_const(8)
    // stack: addr08', x08, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1 
    %add_const(9)
    // stack:       addr09, SRC, DEST
    MLOAD_GENERAL
    // stack:         x09, SRC, DEST
    DUP3
    %add_const(9)
    // stack: addr09', x09, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    DUP1
    %add_const(10)
    // stack:       addr10, SRC, DEST
    MLOAD_GENERAL
    // stack:         x10, SRC, DEST
    DUP3
    %add_const(10)
    // stack: addr10', x10, SRC, DEST
    %swap_mstore
    // stack:              SRC, DEST
    %add_const(11)
    // stack:            addr11, DEST
    MLOAD_GENERAL
    // stack:              x11, DEST
    DUP2
    %add_const(11)
    // stack:      addr11', x11, DEST
    %swap_mstore
%endmacro

%macro assert_eq_unit_fp254_12
    %assert_eq_const(1)
    %rep 10
        OR
    %endrep
    %assert_zero
%endmacro
