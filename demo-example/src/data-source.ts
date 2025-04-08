import { DataSource } from 'typeorm';
import { AppUser } from './entities/user.entity';
import { AppRole } from './entities/role.entity';
import path from 'path';

// Using SQLite for simplicity in this demo
export const AppDataSource = new DataSource({
    type: 'sqlite',
    database: path.join(__dirname, '../database.sqlite'),
    synchronize: true, // Don't use this in production!
    logging: true,
    entities: [AppUser, AppRole],
    subscribers: [],
    migrations: [],
});

export default AppDataSource;
