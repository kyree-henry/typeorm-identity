export class ArgumentNullThrowHelper {
    /**
     * Throws an ArgumentNullException if the provided argument is null or undefined.
     * @param arg The argument to check.
     * @param paramName The name of the parameter to include in the exception.
     * @throws {Error} Throws an error if the argument is null or undefined.
     */
    public static ThrowIfNull<T>(arg: T | null | undefined, paramName: string): void {
        if (arg === null || arg === undefined) {
            throw new Error(`${paramName} cannot be null or undefined.`);
        }
    }
}
