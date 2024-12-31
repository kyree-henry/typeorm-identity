import { Claim, IdentityRole, IdentityResult, IdentityError, IdentityRoleClaim, RoleNotFoundError } from "index";
import { IdentityUserRole } from "domain/entities/userRole.entity";
import { FindOptionsWhere, Repository } from "typeorm";
import { ArgumentNullThrowHelper } from "core/utils/argument.util";

export class RoleManager<TRole extends IdentityRole<number | string>> {

    private readonly roleContext: Repository<TRole>;
    private readonly roleClaimContext: Repository<IdentityRoleClaim>;
    private readonly userRoleContext: Repository<IdentityUserRole>;
    constructor(
        roleRepository: Repository<TRole>,
        roleClaimRepository: Repository<IdentityRoleClaim>,
        userRoleRepository: Repository<IdentityUserRole>,
    ) {
        this.roleContext = roleRepository;
        this.roleClaimContext = roleClaimRepository;
        this.userRoleContext = userRoleRepository;
    }

    public async FindByIdAsync(id: number | string): Promise<TRole | null> {

        ArgumentNullThrowHelper.ThrowIfNull(id, "roleId");

        return await this.roleContext.findOne({
            where: { id } as FindOptionsWhere<TRole>,
        });
    }

    public async FindByNameAsync(roleName: string): Promise<TRole | null> {

        ArgumentNullThrowHelper.ThrowIfNull(roleName, "roleName");

        const normalizedName = roleName.normalize("NFC");
        return await this.roleContext.findOne({
            where: { normalizedName: normalizedName } as FindOptionsWhere<TRole>
        });
    }

    public async RoleExistsAsync(roleName: string): Promise<boolean> {

        ArgumentNullThrowHelper.ThrowIfNull(roleName, "roleName");

        return await this.FindByNameAsync(roleName) !== null;
    }

    public async GetClaimsAsync(role: TRole): Promise<Claim[]> {

        ArgumentNullThrowHelper.ThrowIfNull(role, "role");

        const roleExists = await this.FindByIdAsync(role.id);
        if (!roleExists) {
            throw new RoleNotFoundError('', role.id?.toString());
        }

        const claims = await this.roleClaimContext.find({
            where: { roleId: role.id?.toString() }
        });

        if (claims.length === 0) {
            return [];
        }

        const result = claims.map((claim) => new Claim(claim.claimType, claim.claimValue));
        return result;
    }

    // Role Creation
    public async CreateAsync(role: TRole): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(role, "role");

        const validationResult = await this.ValidateRoleAsync(role);
        if (!validationResult.succeeded) return validationResult;

        const existingRole = await this.FindByNameAsync(role.name);
        if (existingRole) {
            const error = new IdentityError(
                'RoleAlreadyExists',
                `A role with the name "${role.name}" already exists.`
            );
            return IdentityResult.Failed(error);
        }

        const saveResult = await this.roleContext.save(role);
        if (saveResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'RoleSaveFailed',
                'There was an error saving the role to the database.'
            );
            return IdentityResult.Failed(error);
        }
    }

    public async UpdateAsync(role: TRole): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(role, "role");

        const validationResult = await this.ValidateRoleAsync(role);
        if (!validationResult.succeeded) return validationResult;

        const existingRole = await this.FindByIdAsync(role.id);
        if (!existingRole) {
            const error = new IdentityError(
                'RoleNotFound',
                `Role with ID "${role.id}" not found.`
            );
            return IdentityResult.Failed(error);
        }

        const updateResult = await this.roleContext.update(role.id as string | number, role as any);

        if (updateResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'RoleUpdateFailed',
                'There was an error updating the role in the database.'
            );
            return IdentityResult.Failed(error);
        }
    }

    public async DeleteAsync(role: TRole): Promise<IdentityResult> {
        
        ArgumentNullThrowHelper.ThrowIfNull(role, "role");

        const existingRole = await this.FindByIdAsync(role.id);
        if (!existingRole) {
            const error = new IdentityError(
                'RoleNotFound',
                `Role with ID "${role.id}" not found.`
            );
            return IdentityResult.Failed(error);
        }

        const usersInRole = await this.userRoleContext.find({ where: { roleId: role.id?.toString() } });
        if (usersInRole && usersInRole.length > 0) {
            const error = new IdentityError(
                'RoleHasUsers',
                `The role "${role.name}" cannot be deleted because there are users assigned to it.`
            );
            return IdentityResult.Failed(error);
        }

        const claimsRemoved = await this.RemoveRoleClaimsAsync(role.id?.toString());
        if (!claimsRemoved) {
            const error = new IdentityError(
                'RoleClaimsRemovalFailed',
                `There was an error removing claims associated with the role "${role.name}".`
            );
            return IdentityResult.Failed(error);
        }

        const deleteResult = await this.roleContext.remove(role);
        if (deleteResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'RoleDeleteFailed',
                'There was an error deleting the role from the database.'
            );
            return IdentityResult.Failed(error);
        }
    }

    // Claims Management 
    public async AddClaimAsync(role: TRole, claim: Claim): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(role, "role");
        ArgumentNullThrowHelper.ThrowIfNull(claim, "claim");

        const existingRole = await this.FindByIdAsync(role.id);
        if (!existingRole) {
            const error = new IdentityError(
                'RoleNotFound',
                `Role with ID "${role.id}" not found.`
            );
            return IdentityResult.Failed(error);
        }

        const existingClaim = await this.FindRoleClaimAsync(role.id?.toString(), claim);
        if (existingClaim) {
            const error = new IdentityError(
                'ClaimAlreadyExists',
                `Claim already exists for the role "${role.name}".`
            );
            return IdentityResult.Failed(error);
        }

        const addResult = await this.roleClaimContext.save({
            roleId: role.id?.toString(),
            claimType: claim.claimType,
            claimValue: claim.claimValue
        });

        if (addResult) {
            return IdentityResult.Success();
        } else {
            const error = new IdentityError(
                'ClaimAddFailed',
                'There was an error adding the claim to the role.'
            );
            return IdentityResult.Failed(error);
        }
    }

    public async RemoveClaimAsync(role: TRole, claim: Claim): Promise<IdentityResult> {

        ArgumentNullThrowHelper.ThrowIfNull(role, "role");
        ArgumentNullThrowHelper.ThrowIfNull(claim, "claim");
        
        const existingRole = await this.FindByIdAsync(role.id);
        if (!existingRole) {
            const error = new IdentityError(
                'RoleNotFound',
                `Role with ID "${role.id}" not found.`
            );
            return IdentityResult.Failed(error);
        }

        const existingClaim = await this.FindRoleClaimAsync(role.id?.toString(), claim);
        if (!existingClaim) {
            const error = new IdentityError(
                'ClaimNotFound',
                `Claim not found for the role "${role.name}".`
            );
            return IdentityResult.Failed(error);
        }

        const removeResult = await this.roleClaimContext.delete({
            roleId: role.id?.toString(),
            claimType: claim.claimType,
            claimValue: claim.claimValue
        });

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

    private async FindRoleClaimAsync(roleId: string, claim: Claim): Promise<Claim | null> {

        ArgumentNullThrowHelper.ThrowIfNull(roleId, "roleId");
        ArgumentNullThrowHelper.ThrowIfNull(claim, "claim");

        const foundClaim = await this.roleClaimContext.findOne({
            where: { roleId, claimType: claim.claimType, claimValue: claim.claimValue }
        });

        if (!foundClaim) {
            return null;
        }

        return new Claim(foundClaim.claimType, foundClaim.claimValue);
    }

    private async RemoveRoleClaimsAsync(roleId: string): Promise<boolean> {

        ArgumentNullThrowHelper.ThrowIfNull(roleId, "roleId");
        
        const result = await this.roleClaimContext.delete({ roleId });
        return result.affected > 0;
    }

    private async ValidateRoleAsync(role: IdentityRole<any>): Promise<IdentityResult> {
        const errors: IdentityError[] = [];

        // Validate role name
        if (!role.name || role.name.trim().length === 0) {
            errors.push(new IdentityError(
                'InvalidName',
                'Role name cannot be empty.'
            ));
        }

        // Optionally, validate the length of the name
        if (role.name.length < 3 || role.name.length > 50) {
            errors.push(new IdentityError(
                'InvalidNameLength',
                'Role name must be between 3 and 50 characters long.'
            ));
        }

        // Validate role description (optional)
        if (role.description && role.description.length > 255) {
            errors.push(new IdentityError(
                'InvalidDescriptionLength',
                'Role description cannot be longer than 255 characters.'
            ));
        }

        // If there are errors, return them
        if (errors.length > 0) {
            return IdentityResult.Failed(...errors);
        }

        // If everything is valid, return success
        return IdentityResult.Success();
    }

}