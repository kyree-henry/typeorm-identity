import { IdentityOptions } from 'core/types/identity.options';
import { IdentityRole } from 'domain/entities/role.entity';
import { IdentityUser } from 'domain/entities/user.entity';
import { Container } from 'typedi';

export function addIdentity<TUser extends IdentityUser<number | string>, TRole extends IdentityRole<number | string>>(options: (options: IdentityOptions) => void) {
    const identityOptions = new IdentityOptions();

    options(identityOptions);

    Container.set('identityOptions', identityOptions);

    return {
        getOptions: () => identityOptions
    };
} 