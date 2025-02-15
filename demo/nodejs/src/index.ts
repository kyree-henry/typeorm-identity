import { AddIdentity, AddTypeOrmDataSource, IdentityOptions } from "typeorm-identity";
import dataSource from "infrastructure/persistence/data.source";
import { ApplicationRole } from "domain/role.entity";
import { ApplicationUser } from "domain/user.entity";
import bodyParser from "body-parser";
import express from "express";
import configs from "./configs";

const app = express();
app.use(bodyParser.json());

const { container } = AddIdentity<ApplicationUser, ApplicationRole>((options: IdentityOptions) => {
  options.signIn.requireConfirmedEmail = true;
});

// AddTypeOrmDataSource(container, dataSource);

const port = configs.port || 3005;
app.listen(port, () => {
  console.log(`server running on port ${port}`);
});