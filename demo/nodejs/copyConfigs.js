const fs = require('fs-extra');
const path = require('path');

const srcDir = path.join(__dirname, 'src', 'configs');
const destDir = path.join(__dirname, 'dist', 'configs');

fs.copy(srcDir, destDir, err => {
  if (err) {
    console.error('Error copying configs directory:', err);
  } else {
    console.log('Configs directory copied successfully.');
  }
});