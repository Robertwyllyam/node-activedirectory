import express, { NextFunction, Request, Response } from "express";
import "express-async-errors";
const app = express();
const PORT = process.argv[2] || 5000;
import ad from "./ldap";
import cors from "cors";
import { Entry } from "ldapts";
import jwt from "jsonwebtoken";

app.use(cors());
app.use(express.json());

app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(
    new Date().toLocaleString("pt-BR"),
    "new request",
    req.ip,
    req.url
  );
  return next();
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if ([username, password].some((i) => !i)) return res.sendStatus(400);
  const auth = await ad.authenticate(username, password);
  if (!auth) return res.sendStatus(401);

  const token = jwt.sign({ username }, process.env.JWT_SECRET as string);
  return res.json({ token });
});

app.get("/validateToken", (req, res) => {
  const { authorization } = req.headers;

  if (!authorization) return res.sendStatus(400);

  const allowed = jwt.verify(authorization, process.env.JWT_SECRET as string);
  return res.send(allowed);
});

app.use((req: Request, res: Response, next: NextFunction) => {
  const { authorization } = req.headers;

  if (!authorization) return res.sendStatus(400);

  const allowed = jwt.verify(authorization, process.env.JWT_SECRET as string);
  if (!allowed) return res.sendStatus(401);
  return next();
});

app.get("/users", async (req, res) => {
  await ad.init();
  const { username } = req.query;
  if (!username) return res.sendStatus(400);
  const user = await ad.getADUser(username as string);
  return res.json(user);
});

app.post("/createUser", async (req, res) => {
  const {
    name,
    username,
    password,
  }: { name: string; username: string; password: string } = req.body;
  await ad.init();
  const newUser = await ad.createADUser(
    username,
    name.split(" ")[0],
    name.split(" ").slice(1).join(` `),
    password
  );
  return res.send("Successfully created!");
});

app.get("/userData", async (req, res) => {
  await ad.init();
  const userData = await ad._performSearch("(objectclass=user)");
  if (userData.length === 0 || !Array.isArray(userData)) {
    return res.sendStatus(400);
  }

  return res.json(
    userData.map((i: Entry) => ({
      name: i.cn,
      description: i.description,
      ...i,
    }))
  );
});

app.get("/adOU", async (req: Request, res: Response) => {
  await ad.init();
  const data = await ad._performSearch(
    "(&(objectClass=organizationalunit))",
    "list"
  );

  if (!Array.isArray(data)) {
    return res.sendStatus(404);
  }

  const targetData = data.filter((i: Entry) => i.dn.includes("PC"));

  return res.json(targetData);
});

app.post("/computers", async (req: Request, res: Response) => {
  const { name, ou } = req.body;
  if ([name, ou].some((i) => !i)) return res.sendStatus(400);

  await ad.init();
  const entry = (await ad.getADComputer(name)) as Entry;
  if (entry) return res.status(400).send("Entry already exists"!);

  await ad.createADComputer(name, ou);
  return res.sendStatus(200);
});

app.get("/computers/:name", async (req: Request, res: Response) => {
  const { name } = req.params;
  if (!name) return res.status(400).send("Please provide a computer");
  await ad.init();
  const result = await ad.getADComputer(name);
  if (!result) return res.status(404).send("Computer not found!");

  return res.json(result);
});

app.delete("/computers/:name", async (req: Request, res: Response) => {
  const { name } = req.params;
  if (!name) return res.status(400).send("Please provide a computer");
  await ad.init();
  const result = await ad.deleteADComputer(name);
  return res.sendStatus(200);
});

app.post("/pwreset", async (req, res) => {
  const { username, password } = req.body;
  console.log("Searching for user");

  await ad.init();
  const user = (await ad.getADUser(username, "sAMAccountName")) as Entry;
  if (!user) return res.status(404).send("user not found");
  await ad.changeUserPassword(username, password);

  return res.sendStatus(200);
});

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.log("Error", err, new Date().toLocaleString("pt-BR"));
  return res.sendStatus(500);
});

app.listen(PORT, () =>
  console.log(`App listening at http://localhost:${PORT}`)
);
