import {it,expect,vi} from 'vitest';
import 'fake-indexeddb/auto';
import {writeVault,readVault,resetPreviewVault,type VaultEnvelope} from '../src/vault';
it('keeps preview and main vaults separate and cannot reset the main database',async()=>{
 const fixture={version:1,kdf:'argon2id',memory:65536,iterations:3,parallelism:1,salt:'AA==',iv:'AA==',ciphertext:'main'} as VaultEnvelope;
 try{
  vi.stubEnv('BASE_URL','/');await writeVault(fixture);await expect(resetPreviewVault()).rejects.toThrow();
  vi.stubEnv('BASE_URL','/preview/');expect(await readVault()).toBeNull();await writeVault({...fixture,ciphertext:'preview'});await resetPreviewVault();expect(await readVault()).toBeNull();
  vi.stubEnv('BASE_URL','/');expect(await readVault()).toEqual(fixture);
 }finally{vi.unstubAllEnvs();}
});
