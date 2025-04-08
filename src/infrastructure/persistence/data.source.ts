import { DataSource } from "typeorm";
import { IdentityUser } from "../../domain/entities/user.entity";
import { IdentityRole } from "../../domain/entities/role.entity";
import { IdentityUserRole } from "../../domain/entities/userRole.entity";
import { IdentityRoleClaim } from "../../domain/entities/roleClaim.entity";
import { IdentityUserClaim } from "../../domain/entities/userClaim.entity";
import { IdentityUserToken } from "../../domain/entities/userToken.entity";

export const AppDataSource = new DataSource({
    type: "postgres", // or your database type
    host: "localhost",
    port: 5432,
    username: "your_username",
    password: "your_password",
    database: "your_database",
    synchronize: true,
    logging: true,
    entities: [
        IdentityUser,
        IdentityRole,
        IdentityUserRole,
        IdentityRoleClaim,
        IdentityUserClaim,
        IdentityUserToken
    ],
    subscribers: [],
    migrations: [],
});

export default AppDataSource;