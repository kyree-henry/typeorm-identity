import { IdentityRole } from "../../domain/entities/role.entity";
import { IdentityUser } from "../../domain/entities/user.entity";
import { IdentityOptions } from "./identity.options";
import { RoleManager } from "../role.manager";
import { UserManager } from "../user.manager";
import { Container } from 'inversify';
import { DataSource } from "typeorm";

export function AddIdentity<TUser extends IdentityUser<number | string>, TRole extends IdentityRole<number | string>>(
    options: (options: IdentityOptions) => void
) {
    const identityOptions = new IdentityOptions();
    options(identityOptions);

    const container = new Container();

    container.bind<IdentityOptions>('IdentityOptions').toConstantValue(identityOptions);
    container.bind('UserManager').to(UserManager<TUser>);
    container.bind('RoleManager').to(RoleManager<TRole>);

    return {
        getOptions: () => identityOptions,
        container
    };
}

export function AddTypeOrmDataSource(container: Container, dataSource: DataSource) {
    dataSource.initialize()
        .then(() => {
            console.log("DataSource has been initialized!");
            container.bind<DataSource>('DataSource').toConstantValue(dataSource);
        })
        .catch((error) => {
            console.error("Error during DataSource initialization:", error);
        });
    return container;
}