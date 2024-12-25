import {
    generateSecurityStamp,
    generateTimestampUUID,
    IdentityUser,
    IdentityError,
    IdentityResult,
    InvalidCredentialsError,
    PasswordReuseError
} from "index";
import { } from "domain/entities/user.entity";
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
    public async CreateAsync(user: TUser, password: string): Promise<IdentityResult> {

        if (await this.FindByEmailAsync(user.email)) {
            const error = new IdentityError(
                'DuplicateEmail',
                `A user with the email "${user.email}" already exists.`
            );
            return IdentityResult.Failed(error);
        }

        if (await this.FindByNameAsync(user.userName)) {
            const error = new IdentityError(
                'DuplicateUserName',
                `A user with the username "${user.userName}" already exists.`
            );
            return IdentityResult.Failed(error);
        }

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.passwordHash = hashedPassword;
        }

        const saved = await this.userContext.save(user);
        if (!saved) {
            const error = new IdentityError(
                'UserSaveFailed',
                'There was an error saving the user to the database.'
            );
            return IdentityResult.Failed(error);
        }

        return IdentityResult.Success();
    }

    public async UpdateAsync(user: TUser): Promise<IdentityResult> {

        const existingUserByEmail = await this.FindByEmailAsync(user.email);
        if (existingUserByEmail && existingUserByEmail.id !== user.id) {
            const error = new IdentityError(
                'DuplicateEmail',
                `A user with the email "${user.email}" already exists.`
            );
            return IdentityResult.Failed(error);
        }

        const existingUserByUsername = await this.FindByNameAsync(user.userName);
        if (existingUserByUsername && existingUserByUsername.id !== user.id) {
            const error = new IdentityError(
                'DuplicateUserName',
                `A user with the username "${user.userName}" already exists.`
            );
            return IdentityResult.Failed(error);
        }

        user.concurrencyStamp = generateTimestampUUID();
        const updateResult = await this.userContext.update(user.id as string | number, user as any);

        if (updateResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'UserUpdateFailed',
                'There was an error updating the user in the database.'
            );
            return IdentityResult.Failed(error);
        }
    }

    // Password Management
    public async CheckPasswordAsync(user: TUser, password: string): Promise<boolean> {
        return await bcrypt.compare(password, user.passwordHash!);
    }

    public async ChangePasswordAsync(user: TUser, currentPassword: string, newPassword: string): Promise<IdentityResult> {

        if (currentPassword === newPassword) {
            const error = new IdentityError(
                'PasswordReuseError',
                'The new password cannot be the same as the current password.'
            );
            return IdentityResult.Failed(error);
        }

        const isCurrentPasswordValid = await this.CheckPasswordAsync(user, currentPassword);
        if (!isCurrentPasswordValid) {
            const error = new IdentityError(
                'InvalidCurrentPassword',
                'The current password is incorrect.'
            );
            return IdentityResult.Failed(error);
        }

        return await this.UpdatePassword(user, newPassword); 
    }

    public async UpdatePassword(user: TUser, newPassword: string): Promise<IdentityResult> {
        const existingUser = await this.FindByIdAsync(user.id);
        if (!existingUser) {
            const error = new IdentityError(
                'UserNotFound',
                `User with ID "${user.id}" not found.`
            );
            return IdentityResult.Failed(error);
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.passwordHash = hashedPassword;

        user.securityStamp = generateSecurityStamp();

        const updateResult = await this.userContext.update(user.id as string | number, user as any);

        if (updateResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'PasswordUpdateFailed',
                'There was an error updating the password.'
            );
            return IdentityResult.Failed(error);
        }
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