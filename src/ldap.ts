import { Client, Attribute, Change, Entry } from "ldapts";
import { config } from "dotenv";
import ssha from "node-ssha256";
config();

function encodePassword(password: string) {
  // @ts-expect-error
  return new Buffer.from('"' + password + '"', "utf16le").toString();
}

class ActiveDirectory {
  baseDN: string;
  username: string;
  password: string;
  url: string;
  client: Client;

  constructor({
    baseDN,
    username,
    password,
    url,
  }: {
    baseDN: string;
    username: string;
    password: string;
    url: string;
  }) {
    this.baseDN = baseDN;
    this.username = username;
    this.password = password;
    this.url = url;
    this.client = new Client({
      url,
      tlsOptions: { rejectUnauthorized: false },
    });
  }

  async init() {
    await this.client.bind(this.username, this.password);
  }

  async _performSearch(filter: string, result?: "unique" | "list") {
    const value = await this.client.search(this.baseDN, { filter });

    if (result === "unique") return value.searchEntries[0];
    return value.searchEntries;
  }

  async _performChange(dn: string, attributeName: string, value: string) {
    const attribute = new Attribute({ type: attributeName, values: [value] });
    const change = new Change({
      operation: "replace",
      modification: attribute,
    });
    return await this.client.modify(dn, change);
  }

  async getADComputer(computerName: string) {
    return await this._performSearch(
      `&(objectclass=user)(cn=${computerName})`,
      "unique"
    );
  }

  async getADUser(
    userName: string,
    filterBy: "sAMAccountName" | "name" | "cn" = "sAMAccountName"
  ) {
    const filter = `(${filterBy}=${userName})`;
    return await this._performSearch(`&(objectclass=user)${filter}`, "unique");
  }

  async createADUser(
    userName: string,
    firstName: string,
    surname: string,
    password: string = "changemepass"
  ) {
    return await this.client.add(`CN=${userName},CN=Users,DC=my,DC=com`, {
      cn: userName,
      givenName: firstName,
      objectclass: "user",
      sn: surname,
      uid: userName,
      samAccountName: userName,
      unicodePwd: encodePassword(password),
      userAccountControl: "544",
    });
  }

  async unlockUser(username: string) {
    const user = (await this.getADUser(username)) as Entry;
    if (!user) throw new Error("User not found");

    return await this._performChange(user.dn, "lockoutTime", "0");
  }

  async changeUserPassword(username: string, newPassword: string) {
    const user = (await this.getADUser(username)) as Entry;

    if (!user) throw new Error("User not found");
    const newPass = encodePassword(newPassword);
    return await this._performChange(user.dn, "unicodePwd", newPass);
  }
}

const ad = new ActiveDirectory({
  baseDN: process.env.AD_DN as string,
  username: process.env.AD_USER as string,
  password: process.env.AD_PASSWORD as string,
  url: process.env.AD_URL as string,
});

export default ad;
