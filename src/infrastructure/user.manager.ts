import { InvalidCredentialsError, PasswordReuseError } from "core/errors/password.error";
import { generateSecurityStamp, generateTimestampUUID } from "core/utils/security.util";
import { UserAlreadyExistsError } from "core/errors/user.error";
import { IdentityUser } from "domain/entities/user.entity";
import { FindOptionsWhere, Repository } from "typeorm";
import bcrypt from 'bcrypt';
import crypto from 'crypto';

export class UserManager<TUser extends IdentityUser<number | string>> {

    private readonly encryptionKey = 'your_secret_key';
    private readonly tokenExpirationTime = 3600;

    private ConfirmEmailTokenPurpose = "EmailConfirmation";
    private ResetPasswordTokenPurpose = "ResetPassword";

    private readonly userContext: Repository<TUser>;

    constructor(
        userRepository: Repository<TUser>
    ) {
        this.userContext = userRepository;
    }

    public async FindByNameAsync(userName: string): Promise<TUser | null> {
        return await this.userContext.findOne({
            where: { normalizedUserName: userName?.normalize("NFC") } as FindOptionsWhere<TUser>,
        });
    }

    public async FindByEmailAsync(email: string): Promise<TUser | null> {
        return await this.userContext.findOne({
            where: { normalizedEmail: email?.normalize("NFC") } as FindOptionsWhere<TUser>,
        });
    }

    public async FindByIdAsync(id: number | string): Promise<TUser | null> {
        return await this.userContext.findOne({
            where: { id } as FindOptionsWhere<TUser>,
        });
    }

    // User Creation
    public async CreateAsync(user: TUser, password: string): Promise<TUser> {
        if (await this.FindByEmailAsync(user.email)) {
            throw new UserAlreadyExistsError(user.email);
        }

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.passwordHash = hashedPassword;
        }

        return await this.userContext.save(user);
    }

    public async UpdateAsync(user: TUser): Promise<void> {
        user.concurrencyStamp = generateTimestampUUID();
        await this.userContext.update(user.id as string | number, user as any);
    }

    // Password Management
    public async CheckPasswordAsync(user: TUser, password: string): Promise<boolean> {
        return await bcrypt.compare(password, user.passwordHash!);
    }

    public async ChangePasswordAsync(user: TUser, currentPassword: string, newPassword: string): Promise<void> {

        if (currentPassword === newPassword) {
            throw new PasswordReuseError()
        }

        const isCurrentPasswordValid = await this.CheckPasswordAsync(user, currentPassword);
        if (isCurrentPasswordValid) {
            await this.UpdatePassword(user, newPassword);
        }

        throw new InvalidCredentialsError();
    }

    public async UpdatePassword(user: TUser, newPassword: string): Promise<void> {
        user.passwordHash = await bcrypt.hash(newPassword, 10);
        user.securityStamp = generateSecurityStamp();
        await this.userContext.update(user.id as string | number, user as any);
    }

    // Token Management
    public async GenerateUserTokenAsync(user: TUser, purpose: string): Promise<string> {
        const expiresAt = Math.floor(Date.now() / 1000) + this.tokenExpirationTime;
        const tokenPayload = { userId: user.id, purpose, expiresAt };

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.encryptionKey, 'hex'), iv);
        const encrypted = cipher.update(JSON.stringify(tokenPayload), 'utf8', 'hex') + cipher.final('hex');

        return iv.toString('hex') + encrypted; // Prepend IV to the token
    }

    public async GeneratePasswordResetTokenAsync(user: TUser): Promise<string> {
        return await this.GenerateUserTokenAsync(user, this.ResetPasswordTokenPurpose);
    }

    public async GenerateEmailConfirmationTokenAsync(user: TUser, newEmail: string): Promise<string> {
        return await this.GenerateUserTokenAsync(user, this.ConfirmEmailTokenPurpose + ":" + newEmail);
    }

    public async VerifyUserTokenAsync(purpose: string, token: string): Promise<{ isValid: boolean, userId: string }> {
        const decryptedToken = this.decryptToken(token);
        if (!decryptedToken) {
            return { isValid: false, userId: '' }; // Token is invalid
        }

        const { userId, purpose: tokenPurpose, expiresAt } = decryptedToken;
        if (expiresAt < Math.floor(Date.now() / 1000)) {
            return { isValid: false, userId: '' }; // Token has expired
        }

        return { isValid: tokenPurpose === purpose, userId };
    }

    // Private Methods
    private decryptToken(token: string): any {
        try {
            const iv = Buffer.from(token.slice(0, 32), 'hex'); // Extract IV from the token
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.encryptionKey, 'hex'), iv);
            const decrypted = decipher.update(token.slice(32), 'hex', 'utf8') + decipher.final('utf8');
            return JSON.parse(decrypted);
        } catch (error) {
            return null;
        }
    }

}

