import 'reflect-metadata';
try {
  console.log('Debug: Starting imports...');
  
  // Try importing the DataSource
  const typeorm = require('typeorm');
  console.log('Debug: typeorm imported:', typeof typeorm);
  const { DataSource } = typeorm;
  console.log('Debug: DataSource retrieved:', typeof DataSource);
  
  // Try importing from typeorm-identity
  console.log('Debug: Importing from typeorm-identity...');
  const typeormIdentity = require('typeorm-identity');
  console.log('Debug: typeorm-identity imported:', typeof typeormIdentity);
  const { AddIdentity, AddTypeOrmDataSource, IdentityOptions } = typeormIdentity;
  console.log('Debug: AddIdentity, AddTypeOrmDataSource retrieved');
  
  console.log('Debug: Importing from typeorm-identity/domain...');
  const domain = require('typeorm-identity/domain');
  console.log('Debug: domain imported:', typeof domain);
  const { IdentityUser, IdentityRole } = domain;
  console.log('Debug: IdentityUser, IdentityRole retrieved');
  
  console.log('Debug: Importing from typeorm-identity/infrastructure...');
  const infrastructure = require('typeorm-identity/infrastructure');
  console.log('Debug: infrastructure imported:', typeof infrastructure);
  const { UserManager } = infrastructure;
  console.log('Debug: UserManager retrieved');
  
  console.log('Debug: All imports successful');
} catch (error) {
  console.error('Debug: Error during import:', error);
  process.exit(1);
}

console.log('Starting TypeORM Identity demo...');
