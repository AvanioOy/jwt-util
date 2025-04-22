/**
 * Fix azure multiline env var
 * @param input - input value or undefined
 * @returns fixed value
 */
export function azureMultilineEnvFix(input: string | undefined) {
	if (input === undefined) {
		return undefined;
	}
	return input.replace(/\\n/g, '\n');
}
