/* eslint-disable @typescript-eslint/no-explicit-any */
import 'mocha';
import 'cross-fetch/polyfill';
import * as chai from 'chai';
import {JwtCertStore} from '../src/JwtCertStore';
import {JwtCertManager} from '../src/JwtCertManager';
import * as chaiAsPromised from 'chai-as-promised';

chai.use(chaiAsPromised);

const expect = chai.expect;

let googleCertKids: string[];
let certStore: JwtCertStore;

const GOOGLE_ISSUER = 'https://accounts.google.com';

describe('JwtCertManager', () => {
	before(async () => {
		const res = await fetch('https://www.googleapis.com/oauth2/v3/certs');
		googleCertKids = (await res.json()).keys.map((key: any) => key.kid) as string[];
		certStore = new JwtCertStore();
	});
	it('should get asymmetric key from google', async () => {
		const certMgmr = new JwtCertManager(certStore);
		for (const kid of googleCertKids) {
			expect(await certMgmr.getCert(GOOGLE_ISSUER, kid)).to.be.instanceOf(Buffer);
		}
	});
	it('should get asymmetric key from google with preloading of all current certs', async () => {
		const certMgmr = new JwtCertManager(certStore);
		await certMgmr.loadIssuerCerts(GOOGLE_ISSUER); // preloading certs
		for (const kid of googleCertKids) {
			expect(await certMgmr.getCert(GOOGLE_ISSUER, kid)).to.be.instanceOf(Buffer);
		}
	});
	it('should fail to load asymmetric certs if not in validIssuers list', async () => {
		const certMgmr = new JwtCertManager(certStore, {validIssuers: [], notValidIssuerThrows: true});
		await expect(certMgmr.loadIssuerCerts(GOOGLE_ISSUER)).to.be.rejectedWith(Error, `Issuer '${GOOGLE_ISSUER}' is not in validIssuers list`);
	});
});
