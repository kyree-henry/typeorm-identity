import configs from 'configs';
import * as path from 'path';
import { DataSource, DataSourceOptions } from 'typeorm';
 
export const postgresOptions: DataSourceOptions = {
    type: 'postgres',
    host: configs.postgres.host,
    port: configs.postgres.port,
    username: configs.postgres.username,
    password: configs.postgres.password,
    database: configs.postgres.database,
    synchronize: configs.postgres.synchronize,
    entities: [path.resolve(__dirname + configs.postgres.entities)],
    migrations: [path.resolve(__dirname + configs.postgres.migrations)],
    logging: configs.postgres.logging,
    migrationsRun: configs.postgres.migrationsRun,
};
  
const dataSource = new DataSource(postgresOptions); 
export default dataSource; 