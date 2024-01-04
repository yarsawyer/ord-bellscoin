use bitcoin::{hashes::{ripemd160, sha256}, util::sighash};
use bitcoincore_rpc::jsonrpc::client;

use crate::subcommand::info::TransactionsOutput;

use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    policy::MAX_STANDARD_TX_WEIGHT,
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime, Witness,
  },
  //bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
  bitcoin::blockdata::script::Instruction,
};

#[derive(Serialize)]
struct Output {
  commit: Txid,
  inscription: InscriptionId,
  reveal: Txid,
  fees: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <NOOKPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(
    long,
    default_value = "1.0",
    help = "Use fee rate of <FEE_RATE> nook/vB"
  )]
  pub(crate) fee_rate: FeeRate,
  #[clap(
    long,
    help = "Use <COMMIT_FEE_RATE> nook/vbyte for commit transaction.\nDefaults to <FEE_RATE> if unset."
  )]
  pub(crate) commit_fee_rate: Option<FeeRate>,
  #[clap(help = "Inscribe nook with contents of <FILE>")]
  pub(crate) file: PathBuf,
  #[clap(long, help = "Do not back up recovery key.")]
  pub(crate) no_backup: bool,
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
  )]
  pub(crate) no_limit: bool,
  #[clap(long, help = "Don't sign or broadcast transactions.")]
  pub(crate) dry_run: bool,
  #[clap(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Option<Address>,
}

impl Inscribe {
  pub(crate) fn run(self, options: Options) -> Result {
    let inscription = Inscription::from_file(options.chain(), &self.file)?;

    let index = Index::open(&options)?;
    index.update()?;

    let client = options.dogecoin_rpc_client_for_wallet_command(false)?;

    let utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;

    let inscriptions = index.get_inscriptions(None)?;

    let commit_tx_change = get_change_address(&client)?;
    let commit_priv_key = get_priv_key(&client, &commit_tx_change)?;

    let reveal_tx_destination = self
      .destination
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;

    

    let mut txs =
      Inscribe::create_inscription_transactions(
        &client,
        self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        commit_priv_key,
        reveal_tx_destination,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.no_limit,
      )?;

    let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&txs.pop().unwrap(), None, None)?
        .hex;

    println!("{:?}", hex::encode(signed_raw_commit_tx));

    let signed_raw_commit_tx1 = client
    .sign_raw_transaction_with_wallet(&txs.pop().unwrap(), None, None)?
    .hex;

    println!("{:?}", hex::encode(signed_raw_commit_tx1));

    // utxos.insert(
    //   reveal_tx.input[0].previous_output,
    //   Amount::from_sat(
    //     unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
    //   ),
    // );

    // let fees =
    //   Self::calculate_fee(&unsigned_commit_tx, &utxos) + Self::calculate_fee(&reveal_tx, &utxos);

    // if self.dry_run {
    //   print_json(Output {
    //     commit: unsigned_commit_tx.txid(),
    //     reveal: reveal_tx.txid(),
    //     inscription: reveal_tx.txid().into(),
    //     fees,
    //   })?;
    // } else {
    //   // removed cause wtf
    //   //if !self.no_backup {
    //   //  Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
    //   //}

    //   let signed_raw_commit_tx = client
    //     .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
    //     .hex;

    //   let commit = client
    //     .send_raw_transaction(&signed_raw_commit_tx)
    //     .context("Failed to send commit transaction")?;

    //   let reveal = client
    //     .send_raw_transaction(&reveal_tx)
    //     .context("Failed to send reveal transaction")?;

    //   print_json(Output {
    //     commit,
    //     reveal,
    //     inscription: reveal.into(),
    //     fees,
    //   })?;
    // };

    Ok(())
  }

  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
    tx.input
      .iter()
      .map(|txin| utxos.get(&txin.previous_output).unwrap().to_sat())
      .sum::<u64>()
      .checked_sub(tx.output.iter().map(|txout| txout.value).sum::<u64>())
      .unwrap()
  }


  fn create_inscription_transactions(
    client: &Client,
    satpoint: Option<SatPoint>,
    inscription: Inscription,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    network: Network,
    utxos_in: BTreeMap<OutPoint, Amount>,
    change: Address,
    change_private_key: PrivateKey,
    destination: Address,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    no_limit: bool,
  ) -> Result<(Vec<bitcoin::Transaction>)> {

    println!("Creating inscription transactions");

    let mut utxos = utxos_in.clone();

    println!("utxos: {:?}", &utxos);

    let satpoint = if let Some(satpoint) = satpoint {
      satpoint
    } else {
      let inscribed_utxos = inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      utxos
        .keys()
        .find(|outpoint| !inscribed_utxos.contains(outpoint))
        .map(|outpoint| SatPoint {
          outpoint: *outpoint,
          offset: 0,
        })
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
    };

    for (inscribed_satpoint, inscription_id) in &inscriptions {
      if inscribed_satpoint == &satpoint {
        return Err(anyhow!("sat at {} already inscribed", satpoint));
      }

      if inscribed_satpoint.outpoint == satpoint.outpoint {
        return Err(anyhow!(
          "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
          satpoint.outpoint,
        ));
      }
    }

    
    const PROTOCOL_ID: &[u8] = b"ord";

    // Build full inscription script and chunk it into 240-byte chunks.
    let mut builder = script::Builder::new();

    let mut parts = Vec::new();

    if let Some(body) = &inscription.body() {
      for chunk in body.chunks(240) {
        parts.push(chunk);        
      }
    }

    builder = builder.push_slice(PROTOCOL_ID);
    builder = builder.push_int(parts.len() as i64);
    builder = builder.push_slice(&inscription.get_content_type_as_ref().unwrap());
    

    for (n, part) in parts.iter().enumerate() {
      builder = builder
                .push_int(parts.len() as i64 - n as i64 -1)
                .push_slice(part);    
    }


    let script = builder.into_script();

    // Create a vector of txs

    let mut txs:Vec<Transaction> = Vec::new();
    let mut last_lock: Option<Script> = None;
    let mut last_partial: Option<Script> = None;
    let mut p2sh_input: Option<TxIn> = None;
    
    let mut instructions = VecDeque::from_iter(script.instructions().flatten());
    

    let mut partial_chunks = vec![];

    while !instructions.is_empty() { 
      let mut chunks_bytes_len = 0;

      if txs.is_empty() {
        partial_chunks.push(instructions.pop_front().unwrap());

        chunks_bytes_len += match partial_chunks.last().unwrap() {
            Instruction::PushBytes(x) => x.len(),
            Instruction::Op(_) => 1,
        };        
      }

      while chunks_bytes_len <= 1500 && !instructions.is_empty() {

        partial_chunks.push(instructions.pop_front().unwrap());
        chunks_bytes_len += match partial_chunks.last().unwrap() {
          Instruction::PushBytes(x) => x.len(),
          Instruction::Op(_) => 1,
        };

        partial_chunks.push(instructions.pop_front().unwrap());
        chunks_bytes_len += match partial_chunks.last().unwrap() {
            Instruction::PushBytes(x) => x.len(),
            Instruction::Op(_) => 1,
        };
      }

      if chunks_bytes_len > 1500 {

        // we don't need len here, as we have already checked that the length is > 1500

        // chunks_bytes_len -= match partial_chunks.last().unwrap() {
        //   Instruction::PushBytes(x) => x.len(),
        //   Instruction::Op(_) => 1,
        // };
        instructions.push_front(partial_chunks.pop().unwrap());

        // chunks_bytes_len -= match partial_chunks.last().unwrap() {
        //   Instruction::PushBytes(x) => x.len(),
        //   Instruction::Op(_) => 1,
        // };

        instructions.push_front(partial_chunks.pop().unwrap());
      }

 

      // Build lockscript
      let secp = Secp256k1::new();


      let mut temp_lock = script::Builder::new()
        .push_slice(change_private_key.public_key(&secp).to_bytes().as_slice())
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY);

      for _ in &partial_chunks {
        temp_lock = temp_lock.push_opcode(opcodes::all::OP_DROP);
      }
      temp_lock = temp_lock.push_opcode(opcodes::OP_TRUE);

      //println!("lockscript: {}", &temp_lock.into_script());

      last_lock = Some(temp_lock.clone().into_script());
      //println!("last_lock: {}", last_lock.unwrap());


      //let lockhash = ripemd160::Hash::hash(&sha256::Hash::hash(&temp_lock.into_script().to_bytes()));

      let p2sh = temp_lock.into_script().to_p2sh();


      // let p2sh = script::Builder::new()
      //     .push_opcode(opcodes::all::OP_HASH160)  
      //     .push_slice(&lockhash)
      //     .push_opcode(opcodes::all::OP_EQUAL);
      
      
      let p2sh_output = TxOut {
        value: 100000,
        script_pubkey: p2sh,
      };

      let mut tx = Transaction {
        version: 1,
        lock_time: PackedLockTime::ZERO,
        input: vec![],
        output: vec![p2sh_output]
      };


      
      if let Some(ref p2sh_input) = p2sh_input {
        tx.input.push(p2sh_input.clone());
      }


      // fund tx 

      let mut found = None;

      let inscribed_utxos = inscriptions        
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      for (utxo, _) in &utxos {
        if inscribed_utxos.contains(utxo) {
          continue;
        }
    
        let value = utxos[utxo];
    
        if value >= bitcoin::Amount::from_sat(100000) {
          found = Some((*utxo, value));
          break;
        }
      }

      if let Some((utxo, value)) = found {
        let input = TxIn {
          previous_output: utxo,
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
          script_sig: Script::default(),
          witness: Witness::new(),
        };
        tx.input.push(input);

        

        utxos.remove(&utxo);
        println!("utxos: {:?}", &utxos);
      }

      if let Some(ref p2sh_input) = p2sh_input {
        use bitcoin::blockdata::transaction::EcdsaSighashType;

        if let Some(ref last_partial) = last_partial {
          if let Some(ref last_lock) = last_lock {

            let sighash_type = EcdsaSighashType::All;
            let sighash_cache = SighashCache::new(&tx);
            let sighash = sighash_cache.legacy_signature_hash(0, &last_lock, sighash_type as u32).unwrap();
        
            let secp256k1 = Secp256k1::new();
            let secret_key: SecretKey = SecretKey::from_slice(&change_private_key.to_bytes()).expect("Invalid private key");

            let signature = secp256k1.sign_ecdsa(
             &secp256k1::Message::from_slice(sighash.to_vec().as_slice())
               .expect("should be cryptographically secure hash"),
             &secret_key,
            );
        
            let serialized_signature = signature.serialize_der();
            let mut txsignature = serialized_signature.to_vec();
            txsignature.push(EcdsaSighashType::All as u8);



            // unlock builder
            

            let mut unlock = script::Builder::new();
            
            let mut chunk_iter = last_partial.instructions();
            while let Some(instruction) = chunk_iter.next() { 
              match instruction {
                Ok(Instruction::Op(op)) => {
                  unlock = unlock.push_opcode(op);
                },
                Ok(Instruction::PushBytes(data)) => {
                  unlock = unlock.push_slice(data);
                },
                Err(e) => {
                  println!("Error processing instruction: {}", e);
                },
              }
            }

            unlock = unlock
              .push_slice(&txsignature)
              .push_slice(&last_lock.as_bytes());

            tx.input[0].script_sig = unlock.into_script();



          
          }
        }
      }

      txs.push(tx.clone());



      let signed_raw_commit_tx = client
      .sign_raw_transaction_with_wallet(&tx, None, None)?
      .hex;
      
      use bitcoin::consensus::encode::deserialize;

      let signed_tx = deserialize::<bitcoin::Transaction>(&signed_raw_commit_tx)?;

      println!("TX: {:?}", hex::encode(signed_raw_commit_tx));      
      println!("TXID: {:?}", signed_tx.txid());

      p2sh_input = Some(TxIn {
        previous_output: OutPoint::new(signed_tx.txid(), 0),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        script_sig: Script::default(),
        witness: Witness::new(),
      });

      let mut partial_script = script::Builder::new();
      for chunx in &partial_chunks {
        match chunx {
          Instruction::Op(op) => {
            partial_script = partial_script.push_opcode(*op);
          },
          Instruction::PushBytes(x) =>  {
            partial_script = partial_script.push_slice(x);
          },
        }
      }

      last_partial = Some(partial_script.into_script());



    }
    let dest = TxOut {
      value: 100000,
      script_pubkey: destination.script_pubkey()
    };
  
    
    let mut tx = Transaction {
      version: 1,
      lock_time: PackedLockTime::ZERO,
      input: vec![p2sh_input.unwrap()],
      output: vec![dest]
    };


    // fund tx 

    let mut found = None;

    let inscribed_utxos = inscriptions        
            .keys()
            .map(|satpoint| satpoint.outpoint)
            .collect::<BTreeSet<OutPoint>>();
    
    for (utxo, _) in &utxos {
      if inscribed_utxos.contains(utxo) {
          continue;
      }
        
      let value = utxos[utxo];
        
      if value >= bitcoin::Amount::from_sat(100000) {
          found = Some((*utxo, value));
          break;
      }
    }
    
    if let Some((utxo, value)) = found {
      let input = TxIn {
          previous_output: utxo,
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
          script_sig: Script::default(),
          witness: Witness::new(),
      };

      utxos.remove(&utxo);
      
      tx.input.push(input);
    }

    if let Some(ref last_partial) = last_partial {
      if let Some(ref last_lock) = last_lock {
          use bitcoin::blockdata::transaction::EcdsaSighashType;

          let sighash_type = EcdsaSighashType::All;
          let sighash_cache = SighashCache::new(&tx);
          let sighash = sighash_cache.legacy_signature_hash(0, &last_lock, sighash_type as u32).unwrap();
      
          let secp256k1 = Secp256k1::new();
          let secret_key: SecretKey = SecretKey::from_slice(&change_private_key.to_bytes()).expect("Invalid private key");

          let signature = secp256k1.sign_ecdsa(
           &secp256k1::Message::from_slice(sighash.to_vec().as_slice())
             .expect("should be cryptographically secure hash"),
           &secret_key,
          );
      
          let serialized_signature = signature.serialize_der();
          let mut txsignature = serialized_signature.to_vec();
          txsignature.push(EcdsaSighashType::All as u8);

          //println!("last partial: {}", hex::encode(last_partial.as_bytes()));


          // unlock builder
            

          let mut unlock = script::Builder::new();
            
          let mut chunk_iter = last_partial.instructions();
          
          while let Some(instruction) = chunk_iter.next() { 
            match instruction {
              Ok(Instruction::Op(op)) => {
                  unlock = unlock.push_opcode(op);
              },
              Ok(Instruction::PushBytes(data)) => {
                  unlock = unlock.push_slice(data);
              },
              Err(e) => {
                  println!("Error processing instruction: {}", e);
              },
            }
          }
          
          unlock = unlock
            .push_slice(&txsignature)
            .push_slice(&last_lock.as_bytes());
          
          tx.input[0].script_sig = unlock.into_script();


      }
    }
    
    txs.push(tx);



    // println!("script original: {}", script);
    // println!("script length: {}", script.len());















    // let secp256k1 = Secp256k1::new();
    // let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
    // let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    

    // let reveal_script = inscription.append_reveal_script(
    //   script::Builder::new()
    //     .push_slice(&public_key.serialize())
    //     .push_opcode(opcodes::all::OP_CHECKSIG),
    // );

    // let taproot_spend_info = TaprootBuilder::new()
    //   .add_leaf(0, reveal_script.clone())
    //   .expect("adding leaf should work")
    //   .finalize(&secp256k1, public_key)
    //   .expect("finalizing taproot builder should work");

    // let control_block = taproot_spend_info
    //   .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
    //   .expect("should compute control block");

    // let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    // let (_, reveal_fee) = Self::build_reveal_transaction(
    //   &control_block,
    //   reveal_fee_rate,
    //   OutPoint::null(),
    //   TxOut {
    //     script_pubkey: destination.script_pubkey(),
    //     value: 0,
    //   },
    //   &reveal_script,
    // );

    // let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
    //   satpoint,
    //   inscriptions,
    //   utxos,
    //   commit_tx_address.clone(),
    //   change,
    //   commit_fee_rate,
    //   reveal_fee + TransactionBuilder::TARGET_POSTAGE,
    // )?;

    // let (vout, output) = unsigned_commit_tx
    //   .output
    //   .iter()
    //   .enumerate()
    //   .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
    //   .expect("should find sat commit/inscription output");

    // let (mut reveal_tx, fee) = Self::build_reveal_transaction(
    //   &control_block,
    //   reveal_fee_rate,
    //   OutPoint {
    //     txid: unsigned_commit_tx.txid(),
    //     vout: vout.try_into().unwrap(),
    //   },
    //   TxOut {
    //     script_pubkey: destination.script_pubkey(),
    //     value: output.value,
    //   },
    //   &reveal_script,
    // );

    // reveal_tx.output[0].value = reveal_tx.output[0]
    //   .value
    //   .checked_sub(fee.to_sat())
    //   .context("commit transaction output value insufficient to pay transaction fee")?;

    // if reveal_tx.output[0].value < reveal_tx.output[0].script_pubkey.dust_value().to_sat() {
    //   bail!("commit transaction output would be dust");
    // }

    // let mut sighash_cache = SighashCache::new(&mut reveal_tx);

    // let signature_hash = sighash_cache
    //   .taproot_script_spend_signature_hash(
    //     0,
    //     &Prevouts::All(&[output]),
    //     TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
    //     SchnorrSighashType::Default,
    //   )
    //   .expect("signature hash should compute");

    // let signature = secp256k1.sign_schnorr(
    //   &secp256k1::Message::from_slice(signature_hash.as_inner())
    //     .expect("should be cryptographically secure hash"),
    //   &key_pair,
    // );

    // let witness = sighash_cache
    //   .witness_mut(0)
    //   .expect("getting mutable witness reference should work");
    // witness.push(signature.as_ref());
    // witness.push(reveal_script);
    // witness.push(&control_block.serialize());

    // let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    // let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    // assert_eq!(
    //   Address::p2tr_tweaked(
    //     TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
    //     network,
    //   ),
    //   commit_tx_address
    // );

    // let reveal_weight = reveal_tx.weight();

    // if !no_limit && reveal_weight > MAX_STANDARD_TX_WEIGHT.try_into().unwrap() {
    //   bail!(
    //     "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
    //   );
    // }

    // Ok((unsigned_commit_tx, reveal_tx, recovery_key_pair))
    Ok(txs)
  }


  fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    output: TxOut,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: vec![TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: vec![output],
      lock_time: PackedLockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[0].witness.push(script);
      reveal_tx.input[0].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.vsize())
    };

    (reveal_tx, fee)
  }
}