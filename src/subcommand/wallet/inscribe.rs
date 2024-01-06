//use bitcoin::{hashes::{ripemd160, sha256}, util::sighash};
//use bitcoincore_rpc::jsonrpc::client;

//use crate::subcommand::info::TransactionsOutput;

use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    policy::MAX_STANDARD_TX_WEIGHT,
    secp256k1::{
      self, Secp256k1,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    PackedLockTime, Witness,
  },
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
    default_value = "2000.0",
    help = "Use fee rate of <FEE_RATE> nook/vB"
  )]
  pub(crate) fee_rate: FeeRate,
  #[clap(
    long,
    help = "Use <COMMIT_FEE_RATE> nook/vbyte for commit transactions.\nDefaults to <FEE_RATE> if unset."
  )]
  pub(crate) commit_fee_rate: Option<FeeRate>,
  #[clap(help = "Inscribe nook with contents of <FILE>")]
  pub(crate) file: PathBuf,
  #[clap(long, help = "Do not back up recovery key.")]
  pub(crate) no_backup: bool,
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bellsd in its default configuration. Do not use this flag unless you understand the implications."
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

    let change_address = get_change_address(&client)?;


    let reveal_tx_destination = self
      .destination
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;

    

    let mut txs =
      Inscribe::create_inscription_transactions(
        &client,
        None, //self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        commit_priv_key,
        change_address,
        reveal_tx_destination,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.no_limit,
      )?;
    
    //println!("{:?}", txs);

    for tx in txs {
      let signed_raw_tx = client
      .sign_raw_transaction_with_wallet(&tx, None, None)?
      .hex;
      
      if self.dry_run {
        println!("{:?}", hex::encode(&signed_raw_tx));
      } else {

      let commit = client
          .send_raw_transaction(&signed_raw_tx)
          .context("Failed to send transaction")?;
      
        println!("TXID: {:?}",commit)
      }

    }




    


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
    change_address: Address,
    destination: Address,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    no_limit: bool,
  ) -> Result<Vec<bitcoin::Transaction>> {


    let mut utxos = utxos_in.clone();

    //println!("utxos: {:?}", &utxos);

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
    



    while !instructions.is_empty() { 
      let mut partial_chunks = vec![];

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
        instructions.push_front(partial_chunks.pop().unwrap());
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

      //println!("lockscript: {}", temp_lock.clone().into_script());

      //last_lock = Some(temp_lock.clone().into_script());
      //println!("last_lock: {}", last_lock.unwrap());


      let p2sh = temp_lock.clone().into_script().to_p2sh();

      //println!("p2sh: {:?}",p2sh);



      
      let p2sh_output = TxOut {
        value: 10000,
        script_pubkey: p2sh,
      };

      let change = TxOut {
        value: 0,
        script_pubkey: change_address.script_pubkey()
      };

      let mut tx = Transaction {
        version: 1,
        lock_time: PackedLockTime::ZERO,
        input: vec![],
        output: vec![p2sh_output,change]
      };


      
      if let Some(ref p2sh_input) = p2sh_input {
        println!("ADD INPUT: {:?}", p2sh_input.clone());
        tx.input.push(p2sh_input.clone());
      }


      // estimate fee

      let mut size_unlock =0;
      if let Some(ref last_partial) = last_partial {
        if let Some(ref last_lock) = last_lock {
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
                  bail!("Error processing instruction: {}", e);
                },
              }
            }
            let zeros = vec![0; 74];
            unlock = unlock
              .push_slice(&zeros)
              .push_slice(&last_lock.as_bytes());

            size_unlock = unlock.into_script().as_bytes().len();
        }
      }

    
      let mut total_value = Amount::from_sat(0);
      let mut selected_utxos = Vec::new();
      let mut tx_size = tx.size()+size_unlock;
  
      let inscribed_utxos = inscriptions        
          .keys()
          .map(|satpoint| satpoint.outpoint)
          .collect::<BTreeSet<OutPoint>>();
      
      for (utxo, _) in &utxos {
        if inscribed_utxos.contains(utxo) {
            continue;
        }
            
        let value = utxos[utxo];
        selected_utxos.push((*utxo, value));
        total_value += value;
            
        let additional_size = 41; // size increase per input
        tx_size += additional_size;
            
        let total_fee = commit_fee_rate.fee(tx_size);
        if total_value >= total_fee + Amount::from_sat(10000) {
              break;
        }
      }
      
      if total_value >= commit_fee_rate.fee(tx_size) + Amount::from_sat(10000) {
        for (utxo, _) in selected_utxos {
            let input = TxIn {
                previous_output: utxo,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                script_sig: Script::default(),
                witness: Witness::new(),
            };
    
            utxos.remove(&utxo);
            tx.input.push(input);
        }
    
        let total_fee = commit_fee_rate.fee(tx_size);
        tx.output[1].value = total_value.to_sat() - total_fee.to_sat() - 10000;
      } else {
        // exit with error
        bail!("Not enough funds to cover the fee and change!");
      }


      if let Some(_) = p2sh_input {
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
                  return Err(e.into());
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

      //println!("TX: {:?}", hex::encode(signed_raw_commit_tx));
      //println!("TXID: {:?}", signed_tx.txid());

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
      last_lock = Some(temp_lock.clone().into_script());

    }
    
    let dest = TxOut {
      value: 100000,
      script_pubkey: destination.script_pubkey()
    };

    let change = TxOut {
      value: 0,
      script_pubkey: change_address.script_pubkey()
    };
  
    
    let mut tx = Transaction {
      version: 1,
      lock_time: PackedLockTime::ZERO,
      input: vec![p2sh_input.unwrap()],
      output: vec![dest,change]
    };

 

    // estimate fee
    let mut size_unlock =0;
    if let Some(ref last_partial) = last_partial {
      if let Some(ref last_lock) = last_lock {
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
                //return Err(e.into());
                bail!("Error processing instruction: {}", e);
              },
            }
          }
          let zeros = vec![0; 74];
          unlock = unlock
            .push_slice(&zeros)
            .push_slice(&last_lock.as_bytes());

          size_unlock = unlock.into_script().as_bytes().len();
      }
    }



    let mut total_value = Amount::from_sat(0);
    let mut selected_utxos = Vec::new();
    let mut tx_size = tx.size()+size_unlock;

    let inscribed_utxos = inscriptions        
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();
    
    for (utxo, _) in &utxos {
      if inscribed_utxos.contains(utxo) {
          continue;
      }
          
      let value = utxos[utxo];
      selected_utxos.push((*utxo, value));
      total_value += value;
          
      let additional_size = 41; // size increase per input
      tx_size += additional_size;
          
      let total_fee = commit_fee_rate.fee(tx_size);
      if total_value >= total_fee + Amount::from_sat(100000) {
            break;
      }
    }
    
    if total_value >= commit_fee_rate.fee(tx_size) + Amount::from_sat(100000) {
      for (utxo, _) in selected_utxos {
          let input = TxIn {
              previous_output: utxo,
              sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
              script_sig: Script::default(),
              witness: Witness::new(),
          };
  
          utxos.remove(&utxo);
          tx.input.push(input);
      }
  
      let total_fee = commit_fee_rate.fee(tx_size);
      tx.output[1].value = total_value.to_sat() - total_fee.to_sat() - 100000;
    } else {
      // exit with error
      bail!("Not enough funds to cover the fee and change!");
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
                bail!("Error processing instruction: {}", e);
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


    Ok(txs)
  }

  
}