import {
    generateSecurityStamp,
    generateTimestampUUID,
    IdentityUser,
    IdentityError,
    IdentityResult,
    InvalidCredentialsError,
    PasswordReuseError,
    IdentityUserClaim,
    IdentityRole,
    RoleNotFoundError,
    IdentityUserRole,
    Claim
} from "index";
import { FindOptionsWhere, Repository } from "typeorm";
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { ArgumentNullThrowHelper } from "core/utils/argument.util";

export class UserManager<TUser extends IdentityUser<number | string>> {

    private readonly encryptionKey = 'your_secret_key';
    private readonly tokenExpirationTime = 3600;

    private ConfirmEmailTokenPurpose = "EmailConfirmation";
    private ResetPasswordTokenPurpose = "ResetPassword";

    private readonly userContext: Repository<TUser>;
    private readonly roleContext: Repository<IdentityRole<number | string>>;
    private readonly userRoleContext: Repository<IdentityUserRole>;
    private readonly userClaimContext: Repository<IdentityUserClaim>;

    constructor(
        userRepository: Repository<TUser>,
        roleRepository: Repository<IdentityRole<number | string>>,
        userRoleRepository: Repository<IdentityUserRole>,
    ) {
        this.userContext = userRepository;
        this.roleContext = roleRepository;
        this.userRoleContext = userRoleRepository;
    }

    public async FindByNameAsync(userName: string): Promise<TUser | null> {

        ArgumentNullThrowHelper.ThrowIfNull(userName, "userName");

        return await this.userContext.findOne({
            where: { normalizedUserName: userName?.normalize("NFC") } as FindOptionsWhere<TUser>,
        });
    }

    public async FindByEmailAsync(email: string): Promise<TUser | null> {

        ArgumentNullThrowHelper.ThrowIfNull(email, "email");

        return await this.userContext.findOne({
            where: { normalizedEmail: email?.normalize("NFC") } as FindOptionsWhere<TUser>,
        });
    }

    public async FindByIdAsync(id: number | string): Promise<TUser | null> {

        ArgumentNullThrowHelper.ThrowIfNull(id, "id");

        return await this.userContext.findOne({
            where: { id } as FindOptionsWhere<TUser>,
        });
    }


    // User Creation
    public async CreateAsync(user: TUser, password: string): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");

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

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");

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

    // LockOut Management
    public async IsLockedOutAsync(user: TUser): Promise<boolean> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");

        if (!user.lockoutEnd) {
            return false; // If lockoutEnd is not set, the user is not locked out
        }

        const currentTime = new Date();
        return user.lockoutEnd > currentTime;
    }


    // Email Management
    public async SetEmailAsync(user: TUser, email: string): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(email, "email");

        const duplicateUser = await this.FindByEmailAsync(email);
        if (duplicateUser) {
            if (duplicateUser.id === user.id) {
                return IdentityResult.Success();
            }

            return IdentityResult.Failed(new IdentityError('EmailAlreadyExists', 
                'This email is already associated with another account.'));
        }

        user.email = email;
        user.emailConfirmed = false;
        user.normalizedEmail = email.normalize("NFC");
        user.concurrencyStamp = generateTimestampUUID();
        const updateResult = await this.userContext.update(user.id as string | number, user as any);

        if (updateResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'SetEmailFailed',
                'There was an error updating the user email in the database.'
            );
            return IdentityResult.Failed(error);
        }
    }

    public async ChangeEmailAsync(newEmail: string, token: string): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(token, "token");
        ArgumentNullThrowHelper.ThrowIfNull(newEmail, "newEmail");

        const { isValid, userId } = await this.VerifyUserTokenAsync(this.ResetPasswordTokenPurpose, token);
        const user = await this.FindByIdAsync(userId as string | number);

        if (!isValid || !user) {
            const error = new IdentityError('InvalidToken', 'The provided token is invalid or expired.');
            return IdentityResult.Failed(error);
        }

        return this.SetEmailAsync(user, newEmail);        
    }

    // Claims Management
    public async GetClaimsAsync(user: TUser): Promise<Claim[]> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");

        const userClaims = await this.userClaimContext.find({ where: { userId: user.id?.toString() } });

        if (!userClaims || userClaims.length === 0) {
            return [];
        }

        const claims: Claim[] = userClaims.map(userClaim => {
            return new Claim(userClaim.claimType, userClaim.claimValue);
        });

        return claims;
    }

    public async AddClaimAsync(user: TUser, claim: Claim): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(claim, "claim");

        const existingClaim = await this.userClaimContext.findOne({
            where: { userId: user.id?.toString(), claimType: claim.claimType, claimValue: claim.claimValue }
        });

        if (existingClaim) {
            const error = new IdentityError(
                "ClaimAlreadyExists",
                `The claim of type '${claim.claimType}' already exists for this user.`);
            return IdentityResult.Failed(error);
        }

        const newClaim = this.userClaimContext.create({
            userId: user.id?.toString(),
            claimType: claim.claimType,
            claimValue: claim.claimValue,
        });

        const saveResult = await this.userClaimContext.save(newClaim);
        if (saveResult) {
            return IdentityResult.Success();
        } else {
            return IdentityResult.Failed(new IdentityError("SaveFailed", "Failed to save user claim."));
        }
    }

    public async AddClaimsAsync(user: TUser, claims: Claim[]): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(claims, "claims");

        const resultList = [];
        for (let claim of claims) {
            const result = await this.AddClaimAsync(user, claim);
            resultList.push(result);
        }

        const hasFailed = resultList.some(result => !result.succeeded);
        if (hasFailed) {
            const errors = resultList
                .filter(result => !result.succeeded)
                .flatMap(result => result.errors);
            return IdentityResult.Failed(...errors);
        }

        return IdentityResult.Success();
    }

    public async RemoveClaimAsync(user: TUser, claim: Claim): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(claim, "claim");

        const existingClaim = await this.userClaimContext.findOne({
            where: { userId: user.id?.toString(), claimType: claim.claimType, claimValue: claim.claimValue }
        });

        if (!existingClaim) {
            return IdentityResult.Failed(new IdentityError("ClaimNotFound", "The claim was not found for the user."));
        }

        const removeResult = await this.userClaimContext.delete(existingClaim);

        if (removeResult.affected > 0) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'ClaimRemoveFailed',
                'There was an error removing the claim from the role.'
            );
            return IdentityResult.Failed(error);
        }
    }

    public async RemoveClaimsAsync(user: TUser, claims: Claim[]): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(claims, "claims");

        const resultList = [];
        for (let claim of claims) {
            const result = await this.RemoveClaimAsync(user, claim);
            resultList.push(result);
        }

        const hasFailed = resultList.some(result => !result.succeeded);
        if (hasFailed) {
            const errors = resultList
                .filter(result => !result.succeeded)
                .flatMap(result => result.errors);
            return IdentityResult.Failed(...errors);
        }

        return IdentityResult.Success();
    }

    public async ReplaceClaimAsync(user: TUser, claim: Claim, newClaim: Claim): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(claim, "claim");
        ArgumentNullThrowHelper.ThrowIfNull(newClaim, "newClaim");

        const existingClaim = await this.userClaimContext.findOne({
            where: { userId: user.id?.toString(), claimType: claim.claimType, claimValue: claim.claimValue }
        });

        if (!existingClaim) {
            return IdentityResult.Failed(new IdentityError("ClaimNotFound", "The claim was not found for the user."));
        }

        existingClaim.claimType = newClaim.claimType;
        existingClaim.claimValue = newClaim.claimValue;

        const updateResult = await this.userClaimContext.save(existingClaim);
        if (updateResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'ReplaceClaimsFailed',
                `Failed to update the claim with type '${existingClaim.claimType}' and value '${existingClaim.claimValue}' for user ID '${existingClaim.userId}'.`
            );
            return IdentityResult.Failed(error);
        }
    }

    // Password Management
    public async CheckPasswordAsync(user: TUser, password: string): Promise<boolean> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(password, "password");

        return await bcrypt.compare(password, user.passwordHash!);
    }

    public async ChangePasswordAsync(user: TUser, currentPassword: string, newPassword: string): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(newPassword, "newPassword");
        ArgumentNullThrowHelper.ThrowIfNull(currentPassword, "currentPassword");

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

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(newPassword, "newPassword");

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

    public async ResetPasswordAsync(token: string, newPassword: string): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(token, "token");
        ArgumentNullThrowHelper.ThrowIfNull(newPassword, "newPassword");

        const { isValid, userId } = await this.VerifyUserTokenAsync(this.ResetPasswordTokenPurpose, token);
        const user = await this.FindByIdAsync(userId as string | number);

        if (!isValid || !user) {
            const error = new IdentityError('InvalidToken', 'The provided token is invalid or expired.');
            return IdentityResult.Failed(error);
        }

        const result = await this.UpdatePassword(user, newPassword);
        return result;
    }

    // Role Management 
    public async GetRolesAsync(user: TUser): Promise<string[]> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");

        const userRoles = await this.userRoleContext.find({ where: { userId: user.id?.toString() } });
        if (!userRoles || userRoles.length === 0) {
            return [];
        }

        const roleNames = await Promise.all(
            userRoles.map(async (userRole: IdentityUserRole) => {
                const role = await this.roleContext.findOne({ where: { id: userRole.roleId } });
                return role?.name;
            })
        );

        return roleNames.filter((name: any) => name !== null) as string[];
    }

    public async IsInRoleAsync(user: TUser, roleName: string): Promise<boolean> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(roleName, "roleName");

        const role = await this.roleContext.findOne({
            where: { name: roleName }
        }) ?? (() => { throw new RoleNotFoundError('', roleName); })();

        const userRole = await this.userRoleContext.findOne({
            where: {
                userId: user.id?.toString(),
                roleId: role.id?.toString()
            }
        });

        return userRole !== null;
    }

    public async AddToRoleAsync(user: TUser, roleName: string): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(roleName, "roleName");

        try {
            const isInRole = await this.IsInRoleAsync(user, roleName);
            if (isInRole) {
                const error = new IdentityError(
                    'User already in role',
                    `User is already in the ${roleName} role.`);
                return IdentityResult.Failed(error);
            }

            const role = await this.roleContext.findOne({ where: { name: roleName } });
            const userRole = new IdentityUserRole(user.id?.toString(), role.id?.toString());
            const saveResult = await this.userRoleContext.save(userRole);
            if (saveResult) {
                return IdentityResult.Success();
            } else {
                const error = new IdentityError(
                    'RoleAssignmentFailed',
                    `Failed to assign the role "${roleName}" to the user. There was an error saving this role in the database.`
                );
                return IdentityResult.Failed(error);
            }
        } catch (error) {
            console.error("Error adding user to role:", error);
            return IdentityResult.Failed(new IdentityError(
                'RoleAssignmentError',
                `An unexpected error occurred while trying to assign the role "${roleName}" to the user. Please check the database or application logs for more details.`
            ));
        }

    }

    public async AddToRolesAsync(user: TUser, roleNames: string[]): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(roleNames, "roleNames");

        try {
            const userRoles = await this.GetRolesAsync(user);
            const rolesToAdd = roleNames.filter(role => !userRoles.includes(role));
            if (rolesToAdd.length === 0) {
                return IdentityResult.Failed(new IdentityError('UserAlreadyInRoles', 'User is already assigned to all provided roles.'));
            }

            const resultList: IdentityResult[] = [];

            for (const roleName of rolesToAdd) {
                const result = await this.AddToRoleAsync(user, roleName);
                resultList.push(result);
            }

            const hasFailed = resultList.some(result => !result.succeeded);

            if (hasFailed) {
                const errors = resultList
                    .filter(result => !result.succeeded)
                    .flatMap(result => result.errors);
                return IdentityResult.Failed(...errors);
            }

            return IdentityResult.Success();
        } catch (error) {
            console.error("Error adding user to roles:", error);
            return IdentityResult.Failed(new IdentityError('RoleAssignmentError', 'Error assigning roles.'));
        }
    }

    // Token Management
    public async GenerateUserTokenAsync(user: TUser, purpose: string): Promise<string> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(purpose, "purpose");

        const expiresAt = Math.floor(Date.now() / 1000) + this.tokenExpirationTime;
        const tokenPayload = { userId: user.id, purpose, expiresAt };

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.encryptionKey, 'hex'), iv);
        const encrypted = cipher.update(JSON.stringify(tokenPayload), 'utf8', 'hex') + cipher.final('hex');

        return iv.toString('hex') + encrypted; // Prepend IV to the token
    }

    public async GeneratePasswordResetTokenAsync(user: TUser): Promise<string> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");

        return await this.GenerateUserTokenAsync(user, this.ResetPasswordTokenPurpose);
    }

    public async GenerateEmailConfirmationTokenAsync(user: TUser, newEmail: string): Promise<string> {

        ArgumentNullThrowHelper.ThrowIfNull(user, "user");
        ArgumentNullThrowHelper.ThrowIfNull(newEmail, "newEmail");

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