import 'mocha';
import * as fs from 'fs';
import * as chai from 'chai';
import {JwtCertStore} from '../src/JwtCertStore';
import * as chaiAsPromised from 'chai-as-promised';

chai.use(chaiAsPromised);

const expect = chai.expect;

const LOCAL_ISSUER = 'https://localhost:3000';
const CACHE_FILE = './test/cache.json';

describe('JwtCertStore', () => {
	before(() => {
		if (fs.existsSync(CACHE_FILE)) {
			fs.unlinkSync(CACHE_FILE);
		}
	});
	it('should store and load symmetric key', async () => {
		const certStore = new JwtCertStore();
		await certStore.init();
		await expect(certStore.isEmpty()).eventually.be.eq(true);
		await certStore.addCert(LOCAL_ISSUER, '01', 'symmetric', 'test');
		await expect(certStore.isEmpty()).eventually.be.eq(false);
		await expect(certStore.haveIssuer(LOCAL_ISSUER)).eventually.be.eq(true);
		await expect(certStore.getCert(LOCAL_ISSUER, '01')).eventually.be.eq('test');
	});
	it('should store and load asymmetric key', async () => {
		const certStore = new JwtCertStore();
		await certStore.init();
		await expect(certStore.isEmpty()).eventually.be.eq(true);
		await certStore.addCert(LOCAL_ISSUER, '01', 'asymmetric', Buffer.from('test'));
		await expect(certStore.isEmpty()).eventually.be.eq(false);
		await expect(certStore.haveIssuer(LOCAL_ISSUER)).eventually.be.eq(true);
		await expect(certStore.getCert(LOCAL_ISSUER, '01')).eventually.be.eql(Buffer.from('test'));
	});
	it('should write cache store and reload', async () => {
		let certStore = new JwtCertStore({cacheFileName: CACHE_FILE, cachePretty: true});
		await certStore.init();
		await expect(certStore.isEmpty()).eventually.be.eq(true);
		await certStore.addCert(LOCAL_ISSUER, '01', 'asymmetric', Buffer.from('test'));
		await expect(certStore.isEmpty()).eventually.be.eq(false);
		await expect(certStore.haveIssuer(LOCAL_ISSUER)).eventually.be.eq(true);
		await expect(certStore.getCert(LOCAL_ISSUER, '01')).eventually.be.eql(Buffer.from('test'));
		// load new instance with cache
		certStore = new JwtCertStore({cacheFileName: CACHE_FILE, cachePretty: true});
		await certStore.init();
		await expect(certStore.isEmpty()).eventually.be.eq(false);
		await expect(certStore.haveIssuer(LOCAL_ISSUER)).eventually.be.eq(true);
		await expect(certStore.getCert(LOCAL_ISSUER, '01')).eventually.be.eql(Buffer.from('test'));
	});
	afterEach(() => {
		if (fs.existsSync(CACHE_FILE)) {
			fs.unlinkSync(CACHE_FILE);
		}
	});
});
