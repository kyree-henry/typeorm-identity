import { AddIdentity } from "typeorm-identity";
import bodyParser from "body-parser";
import express from "express";
import configs from "./configs";
const app = express();
app.use(bodyParser.json());
const { container } = AddIdentity((options) => {
    options.signIn.requireConfirmedEmail = true;
});
const port = configs.port || 3005;
app.listen(port, () => {
    console.log(`server running on port ${port}`);
});
//# sourceMappingURL=index.js.map