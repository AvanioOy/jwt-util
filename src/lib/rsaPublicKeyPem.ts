// http://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js

/**
 * Converts a base64-encoded RSA public key modulus and exponent into a PEM-formatted string.
 * @param modulusB64 - The base64-encoded modulus of the RSA public key.
 * @param exponentB64 - The base64-encoded exponent of the RSA public key.
 * @returns The PEM-formatted RSA public key as a string.
 */
export function rsaPublicKeyPem(modulusB64: string, exponentB64: string): string {
	const modulus = Buffer.from(modulusB64, 'base64');
	const exponent = Buffer.from(exponentB64, 'base64');

	let modulusHex = modulus.toString('hex');
	let exponentHex = exponent.toString('hex');

	modulusHex = prePadSigned(modulusHex);
	exponentHex = prePadSigned(exponentHex);

	const modLen = modulusHex.length / 2;
	const expLen = exponentHex.length / 2;

	const encodedModLen = encodeLengthHex(modLen);
	const encodedExpLen = encodeLengthHex(expLen);
	const encodedPubkey =
		'30' +
		encodeLengthHex(modLen + expLen + encodedModLen.length / 2 + encodedExpLen.length / 2 + 2) +
		'02' +
		encodedModLen +
		modulusHex +
		'02' +
		encodedExpLen +
		exponentHex;

	return Buffer.from(encodedPubkey, 'hex').toString('base64').toString();
}

export const buildCertFrame = (der: string): Buffer => {
	const match = der.toString().match(/.{1,64}/g);
	if (!match) {
		throw new Error('Cert data error');
	}
	return Buffer.from('-----BEGIN RSA PUBLIC KEY-----\r\n' + match.join('\r\n') + '\r\n-----END RSA PUBLIC KEY-----\r\n');
};

function prePadSigned(hexStr: string) {
	const msb = hexStr[0];
	if (msb !== undefined && (msb < '0' || msb > '7')) {
		return '00' + hexStr;
	} else {
		return hexStr;
	}
}

/**
 * Converts a number to a hexadecimal string representation.
 * If the resulting string has an odd length, a leading zero is added.
 * @param numberValue The number to convert.
 * @returns The hexadecimal string representation of the number.
 */
function toHex(numberValue: number) {
	const nStr = numberValue.toString(16);
	if (nStr.length % 2) {
		return '0' + nStr;
	}
	return nStr;
}

// encode ASN.1 DER length field
// if <=127, short form
// if >=128, long form
function encodeLengthHex(n: number) {
	if (n <= 127) {
		return toHex(n);
	} else {
		const nHex = toHex(n);
		const lengthOfLengthByte = 128 + nHex.length / 2; // 0x80 + num bytes
		return toHex(lengthOfLengthByte) + nHex;
	}
}
