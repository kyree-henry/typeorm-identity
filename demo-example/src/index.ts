import 'reflect-metadata';
import express from 'express';
import { AddIdentity, AddTypeOrmDataSource, IdentityOptions } from 'typeorm-identity';
import { AppUser } from './entities/user.entity';
import { AppRole } from './entities/role.entity';
import AppDataSource from './data-source';
import { UserType } from './entities/user.entity';
import { Container } from 'inversify';
import { UserManager } from 'typeorm-identity/infrastructure';
import { Claim } from 'typeorm-identity/domain';

// Initialize Express
const app = express();
app.use(express.json());

// Configure TypeORM Identity
const { container } = AddIdentity<AppUser, AppRole>((options: IdentityOptions) => {
  options.signIn.requireConfirmedEmail = false; // For demo purposes
  options.password.requireDigit = true;
  options.password.requiredLength = 8;
  options.user.allowedUserNameCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+';
});

// Add TypeORM DataSource
const appContainer = AddTypeOrmDataSource(container, AppDataSource);

// Setup routes
app.post('/register', async (req, res) => {
  try {
    const { email, password, fullName, userName } = req.body;
    
    const userManager = appContainer.get<UserManager<AppUser>>('UserManager');
    
    // Create user
    const user = new AppUser();
    user.email = email;
    user.userName = userName;
    user.fullName = fullName;
    user.userType = UserType.Standard;
    
    const result = await userManager.CreateAsync(user, password);
    
    if (result.succeeded) {
      // Add claims
      await userManager.AddClaimAsync(user, new Claim('FullName', fullName));
      
      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: user.id,
          email: user.email,
          userName: user.userName,
          fullName: user.fullName,
          userType: user.userType
        }
      });
    } else {
      res.status(400).json({ errors: result.errors });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const userManager = appContainer.get<UserManager<AppUser>>('UserManager');
    
    // Find user by email
    const user = await userManager.FindByEmailAsync(email);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check password
    const isPasswordValid = await userManager.CheckPasswordAsync(user, password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Successful login
    res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        userName: user.userName,
        fullName: user.fullName,
        userType: user.userType
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('TypeORM Identity Demo');
  console.log('Available endpoints:');
  console.log('- POST /register (email, password, fullName, userName)');
  console.log('- POST /login (email, password)');
});
