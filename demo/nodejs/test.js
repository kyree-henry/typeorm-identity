// Simple test script to verify typeorm-identity works
console.log("Running test script for typeorm-identity");

try {
  // Import required modules
  const typeormIdentity = require("../../dist");
  console.log("Successfully imported typeorm-identity:", Object.keys(typeormIdentity));
  
  // Test if we can access the main functions
  if (typeormIdentity.AddIdentity && typeof typeormIdentity.AddIdentity === "function") {
    console.log("AddIdentity function is available");
  }
  
  if (typeormIdentity.AddTypeOrmDataSource && typeof typeormIdentity.AddTypeOrmDataSource === "function") {
    console.log("AddTypeOrmDataSource function is available");
  }
  
  // Try importing the domain entities
  const domain = require("../../dist/domain");
  console.log("Successfully imported domain entities:", Object.keys(domain));
  
  // Try importing the infrastructure
  const infrastructure = require("../../dist/infrastructure");
  console.log("Successfully imported infrastructure components:", Object.keys(infrastructure));
  
  console.log("Test completed successfully!");
} catch (error) {
  console.error("Error during test:", error);
}
