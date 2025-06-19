#![allow(non_snake_case)]

extern crate rand;
extern crate curve25519_dalek;
extern crate merlin;
extern crate bulletproofs;
//extern crate spock;

use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
use bulletproofs::r1cs::LinearCombination;

use super::r1cs_utils::{AllocatedScalar, constrain_lc_with_scalar};
use super::gadget_zero_nonzero::is_nonzero_gadget;
use super::poseidon_constants::{MDS_ENTRIES, ROUND_CONSTS};
use rand::SeedableRng;
use rand::rngs::StdRng;
use curve25519_dalek::ristretto::CompressedRistretto;

use std::any::Any;
use std::borrow::BorrowMut;
use std::{fmt, mem};
use std::collections::HashMap;

pub trait EvaluatableConstraintSystem: ConstraintSystem {
    fn eval(&self, lc: &LinearCombination) -> Option<Scalar>;
}

impl<'g, T: BorrowMut<Transcript>> EvaluatableConstraintSystem for Prover<'g, T> {
    fn eval(&self, lc: &LinearCombination) -> Option<Scalar> {
        Some(self.eval(lc))
    }
}

impl<T: BorrowMut<Transcript>> EvaluatableConstraintSystem for Verifier<T> {
    fn eval(&self, _lc: &LinearCombination) -> Option<Scalar> {
        None
    }
}

/// Following code for handling Hex is taken from https://play.rust-lang.org/?version=stable&mode=debug&edition=2015&gist=e241493d100ecaadac3c99f37d0f766f
use std::num::ParseIntError;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, DecodeHexError> {
    let s = if s[0..2] == *"0x" || s[0..2] == *"0X" {
        match s.char_indices().skip(2).next() {
            Some((pos, _)) => &s[pos..],
            None => "",
        }
    } else { s };
    if s.len() % 2 != 0 {
        Err(DecodeHexError::OddLength)
    } else {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeHexError {
    OddLength,
    ParseInt(ParseIntError),
}

impl From<ParseIntError> for DecodeHexError {
    fn from(e: ParseIntError) -> Self {
        DecodeHexError::ParseInt(e)
    }
}

impl fmt::Display for DecodeHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeHexError::OddLength => "input string has an odd number of bytes".fmt(f),
            DecodeHexError::ParseInt(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeHexError {}

pub fn get_scalar_from_hex(hex_str: &str) -> Result<Scalar, DecodeHexError> {
    let bytes = decode_hex(hex_str)?;
    let mut result: [u8; 32] = [0; 32];
    result.copy_from_slice(&bytes);
    Ok(Scalar::from_bytes_mod_order(result))
}

// TODO: Add serialization with serde
pub struct PoseidonParams {
    pub width: usize,
    // Number of full SBox rounds in beginning
    pub full_rounds_beginning: usize,
    // Number of full SBox rounds in end
    pub full_rounds_end: usize,
    // Number of partial SBox rounds in beginning
    pub partial_rounds: usize,
    pub round_keys: Vec<Scalar>,
    pub MDS_matrix: Vec<Vec<Scalar>>
}

impl PoseidonParams {
    pub fn new(width: usize, full_rounds_beginning: usize, full_rounds_end: usize, partial_rounds: usize) -> PoseidonParams {
        let total_rounds = full_rounds_beginning + partial_rounds + full_rounds_end;
        let round_keys = Self::gen_round_keys(width, total_rounds);
        let matrix_2 = Self::gen_MDS_matrix(width);
        PoseidonParams {
            width,
            full_rounds_beginning,
            full_rounds_end,
            partial_rounds,
            round_keys,
            MDS_matrix: matrix_2
        }
    }

    // TODO: Write logic to generate correct round keys.
    fn gen_round_keys(width: usize, total_rounds: usize) -> Vec<Scalar> {
        let cap = total_rounds * width;
        /*let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
        vec![Scalar::random(&mut test_rng); cap]*/
        if ROUND_CONSTS.len() < cap {
            panic!("Not enough round constants, need {}, found {}", cap, ROUND_CONSTS.len());
        }
        let mut rc = vec![];
        for i in 0..cap {
            // TODO: Remove unwrap, handle error
            let c = get_scalar_from_hex(ROUND_CONSTS[i]).unwrap();
            rc.push(c);
        }
        rc
    }

    // TODO: Write logic to generate correct MDS matrix. Currently loading hardcoded constants.
    fn gen_MDS_matrix(width: usize) -> Vec<Vec<Scalar>> {
        /*let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
        vec![vec![Scalar::random(&mut test_rng); width]; width]*/
        if MDS_ENTRIES.len() != width {
            panic!("Incorrect width, only width {} is supported now", width);
        }
        let mut mds: Vec<Vec<Scalar>> = vec![vec![Scalar::ZERO; width]; width];
        for i in 0..width {
            if MDS_ENTRIES[i].len() != width {
                panic!("Incorrect width, only width {} is supported now", width);
            }
            for j in 0..width {
                // TODO: Remove unwrap, handle error
                mds[i][j] = get_scalar_from_hex(MDS_ENTRIES[i][j]).unwrap();
            }
        }
        mds
    }

    pub fn get_total_rounds(&self) -> usize {
        self.full_rounds_beginning + self.partial_rounds + self.full_rounds_end
    }
}

/// Simplify linear combination by taking Variables common across terms and adding their corresponding scalars.
/// Useful when linear combinations become large. Takes ownership of linear combination as this function is useful
/// when memory is limited and the obvious action after this function call will be to free the memory held by the passed linear combination
/*fn simplify_lc(lc: LinearCombination) -> LinearCombination {
    // TODO: Move this code to the fork of bulletproofs
    let mut vars: HashMap<Variable, Scalar> = HashMap::new();
    
    let terms = lc.get_terms();
    for (var, val) in terms {
        *vars.entry(var).or_insert(Scalar::ZERO) += val;
    }

    let mut new_lc_terms = vec![];
    for (var, val) in vars {
        new_lc_terms.push((var, val));
    }
    new_lc_terms.iter().collect()
}*/

pub enum SboxType {
    Cube,
    Inverse
}

impl SboxType {
    fn apply_sbox(&self, elem: &Scalar) -> Scalar {
        match self {
            SboxType::Cube => (elem * elem) * elem,
            SboxType::Inverse => elem.invert()
        }
    }

    fn synthesize_sbox<CS: EvaluatableConstraintSystem >(
        &self,
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        match self {
            SboxType::Cube => Self::synthesize_cube_sbox(cs, input_var, round_key),
            SboxType::Inverse => Self::synthesize_inverse_sbox(cs, input_var, round_key),
            _ => Err(R1CSError::GadgetError {description: String::from("Unknown Sbox type")})
        }
    }

    // Allocate variables in circuit and enforce constraints when Sbox as cube
    fn synthesize_cube_sbox<CS: EvaluatableConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;
        let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
        let (_, _, cube) = cs.multiply(sqr.into(), i.into());
        Ok(cube)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as inverse
    fn synthesize_inverse_sbox<CS: EvaluatableConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;

        let a = cs.eval(&inp_plus_const).map(|a| (a, a.invert()));
        
        let (var_l, var_r, var_o) = cs.allocate_multiplier(a)?;
        

        // Constrain product of `inp_plus_const` and its inverse to be 1.
        constrain_lc_with_scalar::<CS>(cs, var_o.into(), &Scalar::ONE);

        Ok(var_r)
    }
}


fn Poseidon_permutation(
    input: &[Scalar],
    params: &PoseidonParams,
    sbox: &SboxType
) -> Vec<Scalar>
{
    let width = params.width;
    assert_eq!(input.len(), width);

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    let mut current_state = input.to_owned();
    let mut current_state_temp = vec![Scalar::ZERO; width];

    let mut round_keys_offset = 0;

    // full Sbox rounds
    for _ in 0..full_rounds_beginning {
        // Sbox layer
        for i in 0..width {
            current_state[i] += params.round_keys[round_keys_offset];
            current_state[i] = sbox.apply_sbox(&current_state[i]);
            round_keys_offset += 1;
        }

        // linear layer
        for j in 0..width {
            for i in 0..width {
                current_state_temp[i] += current_state[j] * params.MDS_matrix[i][j];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp[i];
            current_state_temp[i] = Scalar::ZERO;
        }
    }

    // middle partial Sbox rounds
    for _ in full_rounds_beginning..(full_rounds_beginning+partial_rounds) {
        for i in 0..width {
            current_state[i] += &params.round_keys[round_keys_offset];
            round_keys_offset += 1;
        }

        // partial Sbox layer, apply Sbox to only 1 element of the state.
        // Here the last one is chosen but the choice is arbitrary.
        current_state[width-1] = sbox.apply_sbox(&current_state[width-1]);

        // linear layer
        for j in 0..width {
            for i in 0..width {
                current_state_temp[i] += current_state[j] * params.MDS_matrix[i][j];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp[i];
            current_state_temp[i] = Scalar::ZERO;
        }
    }

    // last full Sbox rounds
    for _ in full_rounds_beginning+partial_rounds..(full_rounds_beginning+partial_rounds+full_rounds_end) {
        // Sbox layer
        for i in 0..width {
            current_state[i] += params.round_keys[round_keys_offset];
            current_state[i] = sbox.apply_sbox(&current_state[i]);
            round_keys_offset += 1;
        }

        // linear layer
        for j in 0..width {
            for i in 0..width {
                current_state_temp[i] += current_state[j] * params.MDS_matrix[i][j];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp[i];
            current_state_temp[i] = Scalar::ZERO;
        }
    }

    // Finally the current_state becomes the output
    current_state
}

pub fn Poseidon_permutation_constraints<'a, CS: EvaluatableConstraintSystem >(
    cs: &mut CS,
    input: Vec<LinearCombination>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType
) -> Result<Vec<LinearCombination>, R1CSError> {
    let width = params.width;
    assert_eq!(input.len(), width);

    fn apply_linear_layer(
        width: usize,
        sbox_outs: Vec<LinearCombination>,
        next_inputs: &mut Vec<LinearCombination>,
        MDS_matrix: &Vec<Vec<Scalar>>,
    ) {
        for j in 0..width {
            for i in 0..width {
                next_inputs[i] = next_inputs[i].clone() + sbox_outs[j].clone() * MDS_matrix[i][j];
            }
        }
    }

    let mut input_vars: Vec<LinearCombination> = input;

    let mut round_keys_offset = 0;

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    // ------------ First rounds with full SBox begin --------------------

    for k in 0..full_rounds_beginning {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset];
            sbox_outputs[i] = sbox_type.synthesize_sbox(cs, input_vars[i].clone(), round_key)?.into();

            round_keys_offset += 1;
        }

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(width, sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        for i in 0..width {
            // replace input_vars with next_input_vars
            input_vars[i] = next_input_vars.remove(0);
        }
    }

    // ------------ First rounds with full SBox begin --------------------

    // ------------ Middle rounds with partial SBox begin --------------------

    for k in full_rounds_beginning..(full_rounds_beginning+partial_rounds) {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset];

            // apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            if i == width-1 {
                sbox_outputs[i] = sbox_type.synthesize_sbox(cs, input_vars[i].clone(), round_key)?.into();
            } else {
                sbox_outputs[i] = input_vars[i].clone() + LinearCombination::from(round_key);
            }

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(width, sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        /*for i in 0..width {
            // replace input_vars with simplified next_input_vars
            input_vars[i] = simplify_lc(next_input_vars.remove(0));
        }*/
    }

    // ------------ Middle rounds with partial SBox end --------------------

    // ------------ Last rounds with full SBox begin --------------------

    for k in (full_rounds_beginning+partial_rounds)..(full_rounds_beginning+partial_rounds+full_rounds_end) {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset];
            sbox_outputs[i] = sbox_type.synthesize_sbox(cs, input_vars[i].clone(), round_key)?.into();

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(width, sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        for i in 0..width {
            // replace input_vars with next_input_vars
            input_vars[i] = next_input_vars.remove(0);
        }
    }

    // ------------ Last rounds with full SBox end --------------------

    Ok(input_vars)
}


pub fn Poseidon_permutation_gadget<'a, CS: EvaluatableConstraintSystem >(
    cs: &mut CS,
    input: Vec<AllocatedScalar>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &[Scalar]
) -> Result<(), R1CSError> {
    let width = params.width;
    assert_eq!(output.len(), width);

    let input_vars: Vec<LinearCombination> = input.iter().map(|e| e.variable.into()).collect();
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, input_vars, params, sbox_type)?;

    for i in 0..width {
        constrain_lc_with_scalar::<CS>(cs, permutation_output[i].to_owned(), &output[i]);
    }

    Ok(())
}

/// 2:1 (2 inputs, 1 output) hash from the permutation by passing the first input as zero, 2 of the next 4 as non-zero, a padding constant and rest zero. Choose one of the outputs.

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub fn Poseidon_hash_2(xl: Scalar, xr: Scalar, params: &PoseidonParams, sbox: &SboxType) -> Scalar {
    // Only 2 inputs to the permutation are set to the input of this hash function,
    // one is set to the padding constant and rest are 0. Always keep the 1st input as 0

    let input = vec![
        Scalar::from(ZERO_CONST),
        xl,
        xr,
        Scalar::from(PADDING_CONST),
        Scalar::from(ZERO_CONST),
        Scalar::from(ZERO_CONST)
    ];

    // Never take the first output
    Poseidon_permutation(&input, params, sbox)[1]
}

pub fn Poseidon_hash_2_constraints<'a, CS: EvaluatableConstraintSystem >(
    cs: &mut CS,
    xl: LinearCombination,
    xr: LinearCombination,
    statics: Vec<LinearCombination>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    let width = params.width;
    // Only 2 inputs to the permutation are set to the input of this hash function.
    assert_eq!(statics.len(), width-2);

    // Always keep the 1st input as 0
    let mut inputs = vec![statics[0].to_owned()];
    inputs.push(xl);
    inputs.push(xr);

    // statics correspond to committed variables with values as PADDING_CONST and 0s and randomness as 0
    for i in 1..statics.len() {
        inputs.push(statics[i].to_owned());
    }
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_2_gadget<'a, CS: EvaluatableConstraintSystem >(
    cs: &mut CS,
    xl: AllocatedScalar,
    xr: AllocatedScalar,
    statics: Vec<AllocatedScalar>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &Scalar
) -> Result<(), R1CSError> {

    let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();
    let hash = Poseidon_hash_2_constraints::<CS>(cs, xl.variable.into(), xr.variable.into(), statics, params, sbox_type)?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}

pub fn Poseidon_hash_4(inputs: [Scalar; 4], params: &PoseidonParams, sbox: &SboxType) -> Scalar {
    // Only 4 inputs to the permutation are set to the input of this hash function,
    // one is set to the padding constant and one is set to 0. Always keep the 1st input as 0

    let input = vec![
        Scalar::from(ZERO_CONST),
        inputs[0],
        inputs[1],
        inputs[2],
        inputs[3],
        Scalar::from(PADDING_CONST)
    ];

    // Never take the first output
    Poseidon_permutation(&input, params, sbox)[1]
}

pub fn Poseidon_hash_4_constraints<'a, CS: EvaluatableConstraintSystem >(
    cs: &mut CS,
    input: [LinearCombination; 4],
    statics: Vec<LinearCombination>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {

    let width = params.width;
    // Only 4 inputs to the permutation are set to the input of this hash function.
    assert_eq!(statics.len(), width-4);

    // Always keep the 1st input as 0
    let mut inputs = vec![statics[0].to_owned()];
    inputs.push(input[0].clone());
    inputs.push(input[1].clone());
    inputs.push(input[2].clone());
    inputs.push(input[3].clone());

    // statics correspond to committed variables with values as PADDING_CONST and 0s and randomness as 0
    for i in 1..statics.len() {
        inputs.push(statics[i].to_owned());
    }
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_4_gadget<'a, CS: EvaluatableConstraintSystem >(
    cs: &mut CS,
    input: Vec<AllocatedScalar>,
    statics: Vec<AllocatedScalar>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &Scalar
) -> Result<(), R1CSError> {

    let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();
    let mut input_arr: [LinearCombination; 4] = [LinearCombination::default(), LinearCombination::default(), LinearCombination::default(), LinearCombination::default()];
    for i in 0..input.len() {
        input_arr[i] = input[i].variable.into();
    }
    let hash = Poseidon_hash_4_constraints::<CS>(cs, input_arr, statics, params, sbox_type)?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}

/// Allocate padding constant and zeroes for Prover
pub fn allocate_statics_for_prover<T: BorrowMut<Transcript>>(prover: &mut Prover<T>, num_statics: usize) -> Vec<AllocatedScalar> {
    let mut statics = vec![];
    let (_, var) = prover.commit(Scalar::from(ZERO_CONST), Scalar::ZERO);
    statics.push(AllocatedScalar {
        variable: var,
        assignment: Some(Scalar::from(ZERO_CONST)),
    });

    // Commitment to PADDING_CONST with blinding as 0
    let (_, var) = prover.commit(Scalar::from(PADDING_CONST), Scalar::ZERO);
    statics.push(AllocatedScalar {
        variable: var,
        assignment: Some(Scalar::from(PADDING_CONST)),
    });

    // Commit to 0 with randomness 0 for the rest of the elements of width
    for _ in 2..num_statics {
        let (_, var) = prover.commit(Scalar::from(ZERO_CONST), Scalar::ZERO);
        statics.push(AllocatedScalar {
            variable: var,
            assignment: Some(Scalar::from(ZERO_CONST)),
        });
    }
    statics
}

/// Allocate padding constant and zeroes for Verifier
pub fn allocate_statics_for_verifier<T: BorrowMut<Transcript>>(verifier: &mut Verifier<T>, num_statics: usize, pc_gens: &PedersenGens) -> Vec<AllocatedScalar> {
    let mut statics = vec![];
    // Commitment to PADDING_CONST with blinding as 0
    let pad_comm = pc_gens.commit(Scalar::from(PADDING_CONST), Scalar::ZERO).compress();

    // Commitment to 0 with blinding as 0
    let zero_comm = pc_gens.commit(Scalar::from(ZERO_CONST), Scalar::ZERO).compress();

    let v = verifier.commit(zero_comm.clone());
    statics.push(AllocatedScalar {
        variable: v,
        assignment: None,
    });

    let v = verifier.commit(pad_comm);
    statics.push(AllocatedScalar {
        variable: v,
        assignment: None,
    });
    for _ in 2..num_statics {
        let v = verifier.commit(zero_comm.clone());
        statics.push(AllocatedScalar {
            variable: v,
            assignment: None,
        });
    }
    statics
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};
    use std::sync::atomic::Ordering::SeqCst;

    fn get_poseidon_params() -> PoseidonParams{
        let width = 6;
        let (full_b, full_e) = (4, 4);
        let partial_rounds = 140;
        PoseidonParams::new(width, full_b, full_e, partial_rounds)
    }

    fn poseidon_perm(sbox_type: &SboxType, transcript_label: &'static [u8]) {
        let s_params = get_poseidon_params();
        let width = s_params.width;
        let total_rounds = s_params.get_total_rounds();

        let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
        let input = (0..width).map(|_| Scalar::random(&mut test_rng)).collect::<Vec<_>>();
        let expected_output = Poseidon_permutation(&input, &s_params, sbox_type);

        /*println!("Input:\n");
        println!("{:?}", &input);
        println!("Expected output:\n");
        println!("{:?}", &expected_output);*/

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2048, 1);

        println!("Proving");
        let mut prover_transcript = Transcript::new(transcript_label);
        let (proof, commitments) = {
            let mut prover = Prover::new(&pc_gens, prover_transcript);

            let mut comms = vec![];
            let mut allocs = vec![];

            for i in 0..width {
                let (com, var) = prover.commit(input[i].clone(), Scalar::random(&mut test_rng));
                comms.push(com);
                allocs.push(AllocatedScalar {
                    variable: var,
                    assignment: Some(input[i]),
                });
            }

            assert!(Poseidon_permutation_gadget(&mut prover,
                                                allocs,
                                                &s_params,
                                                sbox_type,
                                                &expected_output).is_ok());

            println!("For Poseidon permutation rounds {}, metrics: {:?}", total_rounds, &prover.metrics());

            let proof = prover.prove(&bp_gens).unwrap();
            (proof, comms)
        };

        println!("Verifying");

        let mut verifier_transcript = Transcript::new(transcript_label);
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let mut allocs = vec![];
        for i in 0..width {
            let v = verifier.commit(commitments[i]);
            allocs.push(AllocatedScalar {
                variable: v,
                assignment: None,
            });
        }
        assert!(Poseidon_permutation_gadget(&mut verifier,
                                            allocs,
                                            &s_params,
                                            sbox_type,
                                            &expected_output).is_ok());

        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }

    fn poseidon_hash_2(sbox_type: &SboxType, transcript_label: &'static [u8]) {
        let s_params = get_poseidon_params();
        let width = s_params.width;
        let total_rounds = s_params.get_total_rounds();

        let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
        let xl = Scalar::random(&mut test_rng);
        let xr = Scalar::random(&mut test_rng);
        let expected_output = Poseidon_hash_2(xl, xr, &s_params, sbox_type);

        /*println!("Input:\n");
        println!("xl={:?}", &xl);
        println!("xr={:?}", &xr);
        println!("Expected output:\n");
        println!("{:?}", &expected_output);*/

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2048, 1);

        println!("Proving");
        let (proof, commitments) = {
            let mut prover_transcript = Transcript::new(transcript_label);
            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            let mut comms = vec![];

            let (com_l, var_l) = prover.commit(xl.clone(), Scalar::random(&mut test_rng));
            comms.push(com_l);
            let l_alloc = AllocatedScalar {
                variable: var_l,
                assignment: Some(xl),
            };

            let (com_r, var_r) = prover.commit(xr.clone(), Scalar::random(&mut test_rng));
            comms.push(com_r);
            let r_alloc = AllocatedScalar {
                variable: var_r,
                assignment: Some(xr),
            };

            let num_statics = 4;
            let statics = allocate_statics_for_prover(&mut prover, num_statics);

            let start = Instant::now();
            assert!(Poseidon_hash_2_gadget(&mut prover,
                                           l_alloc,
                                           r_alloc,
                                           statics,
                                           &s_params,
                                           sbox_type,
                                           &expected_output).is_ok());

            println!("For Poseidon hash 2:1 rounds {}, metrics: {:?}", total_rounds, &prover.metrics());

            let proof = prover.prove(&bp_gens).unwrap();

            let end = start.elapsed();

            println!("Proving time is {:?}", end);
            (proof, comms)
        };

        println!("Verifying");

        let mut verifier_transcript = Transcript::new(transcript_label);
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let lv = verifier.commit(commitments[0]);
        let rv = verifier.commit(commitments[1]);
        let l_alloc = AllocatedScalar {
            variable: lv,
            assignment: None,
        };
        let r_alloc = AllocatedScalar {
            variable: rv,
            assignment: None,
        };

        let num_statics = 4;
        let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

        let start = Instant::now();
        assert!(Poseidon_hash_2_gadget(&mut verifier,
                                       l_alloc,
                                       r_alloc,
                                       statics,
                                       &s_params,
                                       sbox_type,
                                       &expected_output).is_ok());

        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
        let end = start.elapsed();

        println!("Verification time is {:?}", end);
    }

    fn poseidon_hash_4(sbox_type: &SboxType, transcript_label: &'static [u8]) {
        let s_params = get_poseidon_params();
        let width = s_params.width;
        let total_rounds = s_params.get_total_rounds();

        let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
        let _input = (0..4).map(|_| Scalar::random(&mut test_rng)).collect::<Vec<_>>();
        let mut input = [Scalar::ZERO; 4];
        input.copy_from_slice(_input.as_slice());
        let expected_output = Poseidon_hash_4(input, &s_params, sbox_type);

        /*println!("Input:\n");
        println!("xl={:?}", &xl);
        println!("xr={:?}", &xr);
        println!("Expected output:\n");
        println!("{:?}", &expected_output);*/

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2048, 1);

        println!("Proving");
        let (proof, commitments) = {
            let mut prover_transcript = Transcript::new(transcript_label);
            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            let mut comms = vec![];
            let mut allocs = vec![];

            for inp in input.iter() {
                let (com, var) = prover.commit(inp.clone(), Scalar::random(&mut test_rng));
                comms.push(com);
                allocs.push(AllocatedScalar {
                    variable: var,
                    assignment: Some(inp.clone()),
                });
            }

            let num_statics = 2;
            let statics = allocate_statics_for_prover(&mut prover, num_statics);

            let start = Instant::now();
            assert!(Poseidon_hash_4_gadget(&mut prover,
                                           allocs,
                                           statics,
                                           &s_params,
                                           sbox_type,
                                           &expected_output).is_ok());

            println!("For Poseidon hash 4:1 rounds {}, metrics {:?}", total_rounds, &prover.metrics());

            let proof = prover.prove(&bp_gens).unwrap();

            let end = start.elapsed();

            println!("Proving time is {:?}", end);
            (proof, comms)
        };

        println!("Verifying");

        let mut verifier_transcript = Transcript::new(transcript_label);
        let mut verifier = Verifier::new(verifier_transcript);
        let mut allocs = vec![];
        for com in commitments {
            let v = verifier.commit(com);
            allocs.push({
                AllocatedScalar {
                    variable: v,
                    assignment: None,
                }
            });
        }

        let num_statics = 2;
        let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

        let start = Instant::now();
        assert!(Poseidon_hash_4_gadget(&mut verifier,
                                       allocs,
                                       statics,
                                       &s_params,
                                       sbox_type,
                                       &expected_output).is_ok());

        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
        let end = start.elapsed();

        println!("Verification time is {:?}", end);
    }

    #[test]
    fn test_poseidon_perm_cube_sbox() {
        poseidon_perm(&SboxType::Cube, b"Poseidon_perm_cube");
    }

    #[test]
    fn test_poseidon_perm_inverse_sbox() {
        poseidon_perm(&SboxType::Inverse, b"Poseidon_perm_inverse");
    }

    #[test]
    fn test_poseidon_hash_2_cube_sbox() {
        poseidon_hash_2(&SboxType::Cube, b"Poseidon_hash_2_cube");
    }

    #[test]
    fn test_poseidon_hash_2_inverse_sbox() {
        poseidon_hash_2(&SboxType::Inverse, b"Poseidon_hash_2_inverse");
    }

    #[test]
    fn test_poseidon_hash_4_cube_sbox() {
        poseidon_hash_4(&SboxType::Cube, b"Poseidon_hash_2_cube");
    }

    #[test]
    fn test_poseidon_hash_4_inverse_sbox() {
        poseidon_hash_4(&SboxType::Inverse, b"Poseidon_hash_2_inverse");
    }
}