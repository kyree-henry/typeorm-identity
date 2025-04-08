import * as path from "path";
import * as dotenv from 'dotenv';
import * as Joi from "joi";
const nodeEnv = process.env.NODE_ENV || 'development';
dotenv.config({ path: path.join(process.cwd(), `.env.${nodeEnv}`) });
dotenv.config({ override: true });
const envVarsSchema = Joi.object()
    .keys({
    NODE_ENV: Joi.string()
        .required(),
    PROJECT_NAME: Joi.string(),
    PORT: Joi.number().default(3000),
    JWT_SECRET: Joi.string()
        .default('this is my custom Secret key for authentication')
        .required()
        .description('JWT secret key'),
    JWT_AUDIENCE: Joi.string()
        .default('https://localhost:80')
        .required()
        .description('JWT Audience'),
    JWT_ISSUER: Joi.string()
        .default('https://localhost:80')
        .required()
        .description('JWT Issuer'),
    JWT_ACCESS_EXPIRATION_MINUTES: Joi.string()
        .default('1m')
        .description('minutes after which access tokens expire'),
    JWT_REFRESH_EXPIRATION_HOURS: Joi.string()
        .default('1h')
        .description('hours after which refresh tokens expire'),
    POSTGRES_HOST: Joi.string()
        .default('localhost')
        .description('Postgres host'),
    POSTGRES_PORT: Joi.number()
        .default(5432)
        .description('Postgres host'),
    POSTGRES_USERNAME: Joi.string()
        .default('postgres')
        .description('Postgres username'),
    POSTGRES_PASSWORD: Joi.string()
        .default('postgres')
        .description('Postgres password'),
    POSTGRES_DATABASE: Joi.string()
        .default('default_database')
        .description('Postgres database name'),
    POSTGRES_SYNCHRONIZE: Joi.boolean()
        .default(false)
        .description('Synchronize if true it dosent use migrations'),
    POSTGRES_AUTO_LOAD_ENTITIES: Joi.boolean()
        .default(true)
        .description('For loading all entities automatically'),
    POSTGRES_ENTITIES: Joi.string().description('Postgres entities'),
    POSTGRES_MIGRATIONS: Joi.string().description('Postgres migrations'),
    POSTGRES_LOGGING: Joi.boolean()
        .default(false)
        .description('Postgres logging'),
    POSTGRES_MIGRATIONS_RUN: Joi.boolean()
        .default(false)
        .description('Run migrations after running project')
})
    .unknown();
const { value: envVars, error } = envVarsSchema
    .prefs({ errors: { label: 'key' } })
    .validate(process.env);
if (error) {
    throw new Error(`Config validation error: ${error.message}`);
}
export default {
    env: envVars.NODE_ENV,
    projectName: envVars.PROJECT_NAME,
    port: envVars.PORT,
    postgres: {
        host: envVars.POSTGRES_HOST,
        port: envVars.POSTGRES_PORT,
        username: envVars.POSTGRES_USERNAME,
        password: envVars.POSTGRES_PASSWORD,
        database: envVars.POSTGRES_DATABASE,
        synchronize: envVars.POSTGRES_SYNCHRONIZE,
        autoLoadEntities: envVars.POSTGRES_AUTO_LOAD_ENTITIES,
        entities: envVars.POSTGRES_ENTITIES,
        migrations: envVars.POSTGRES_MIGRATIONS,
        logging: envVars.POSTGRES_LOGGING,
        migrationsRun: envVars.POSTGRES_MIGRATIONS_RUN
    },
    jwt: {
        secret: envVars.JWT_SECRET,
        audience: envVars.JWT_AUDIENCE,
        issuer: envVars.JWT_ISSUER,
        accessTokenExpiration: envVars.JWT_ACCESS_EXPIRATION_MINUTES,
        refreshTokenExpiration: envVars.JWT_REFRESH_EXPIRATION_HOURS,
    }
};
//# sourceMappingURL=configs.js.map