// verify-sal.mjs - Verify SAL credential using Digital Bazaar implementation
// Run: npm install @digitalbazaar/ecdsa-sd-2023-cryptosuite @digitalbazaar/data-integrity jsonld-signatures @digitalbazaar/ecdsa-multikey
// Then: node verify-sal.mjs

import * as ecdsaSd2023Cryptosuite from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';
import {readFileSync} from 'fs';
import {createLoader} from '@digitalbazaar/did-io';
import {documentLoader as defaultLoader} from '@digitalbazaar/jsonld-document-loader';

const {createConfirmCryptosuite} = ecdsaSd2023Cryptosuite;
const {purposes: {AssertionProofPurpose}} = jsigs;

// Read the SAL credential
const credential = JSON.parse(readFileSync('./sg-test-vectors/enc_eapostille_1.json', 'utf-8'));

console.log('Credential ID:', credential.id);
console.log('Issuer:', credential.issuer);
console.log('Proof type:', credential.proof?.type);
console.log('Proof cryptosuite:', credential.proof?.cryptosuite);

// Create a simple document loader that fetches contexts
async function documentLoader(url) {
  console.log('Loading:', url);
  
  // Try fetching from the web
  try {
    const response = await fetch(url);
    if (response.ok) {
      const document = await response.json();
      return {
        contextUrl: null,
        documentUrl: url,
        document
      };
    }
  } catch (e) {
    console.log('Failed to fetch:', url, e.message);
  }
  
  throw new Error(`Failed to load: ${url}`);
}

async function main() {
  try {
    // Try to verify with createConfirmCryptosuite (for base proofs)
    const cryptosuite = createConfirmCryptosuite();
    const suite = new DataIntegrityProof({cryptosuite});
    
    console.log('\nAttempting verification...');
    const result = await jsigs.verify(credential, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader
    });
    
    console.log('\nVerification result:', result.verified);
    if (!result.verified) {
      console.log('Errors:', JSON.stringify(result.error || result.results, null, 2));
    }
  } catch (e) {
    console.error('Error:', e);
  }
}

main();
