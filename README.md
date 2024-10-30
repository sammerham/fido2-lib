# WebAuthn Next.js Project

This project implements (Usernameless-Passwordless) for user registration/authentication using (Fido2-Lib - WebAuthn Native Api and Credential Management Api): it is implemented using Next.js, Prisma, and PostgreSQL. 
Users can register and log in using WebAuthn credentials such as Touch ID, Face ID, or security keys.


## Features

- User registration with WebAuthn.
- User authentication with WebAuthn.
- PostgreSQL database for storing user and passkey data.
- Prisma ORM for database interaction.
- Axios for making API requests.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Node.js and npm installed.
- PostgreSQL installed and running.
- Prisma installed (`npm install prisma --save-dev`).

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/sammerham/fido2-lib.git
   
2. **Navigate to the project directory:**

``` bash
cd fido2-lib
```

3. **Install dependencies:**

``` bash
npm install
```
4. **Set up the environment variables:**

4.1 **Create a .env file in the root directory and add your PostgreSQL database URL:**
DATABASE_URL=postgresql://USERNAME:PASSWORD@localhost:5432/yourdatabasename?schema=public"
JWT_SECRET =""
RP_ID = 'localhost'
EXPECTED_ORIGIN = 'http://localhost:3000'
NODE_ENV = 'development'
**Replace USERNAME, PASSWORD, and localhost:5432 with your actual PostgreSQL credentials.**

5. **Setting Up the Database**
Initialize Prisma:

Run the following command to:

initialize Prisma
```bash
npx prisma init
```
Generate Prisma Client:
```bash
npx prisma generate
```
7- Migrate the database:
``` bash
npx prisma migrate dev --name init
```
Optional: View database with Prisma Studio
You can open Prisma Studio to inspect your database:

```bash
npx prisma studio
``` 

8- **Running the Application**
To start the development server, run:

``` bash
npm run dev
```
**The application will be available at http://localhost:3000.**

9- **API Endpoints**
POST /api/generate-registration-options: Initializes WebAuthn registration for a given email.
POST /api/verify-registration: Verifies the WebAuthn registration and stores the passkey in the database.
POST /api/generate-authentication-options: Initializes WebAuthn authentication for a given email.
POST /api/verify-authentication: Verifies the WebAuthn authentication response.

10 - **Project Structure**
pages/
index.js: Home page with navigation links.
register.js: WebAuthn registration page.
login.js: WebAuthn login page.
api/: Contains API routes for WebAuthn registration and authentication.
prisma/
schema.prisma: Defines the User and PassKey models.
styles/: Global and modular CSS styles.
Prisma Schema
Here is an example of the Prisma schema used in this project:

11 - **prisma**

model User {
  id                  String                  @id 
  webauthnCredentials WebauthnCredential[]
  didKeys             DidKey[]
  createdAt           DateTime                @default(now())
  lastUsed            DateTime
}

model WebauthnCredential {
  id             String     @id 
  userId         String
  credId         String     @unique
  credPublicKey  String
  counter        Int        // Field for storing counter
  deviceType     String
  backEligible   Boolean
  backStatus     Boolean
  createdAt      DateTime   @default(now())
  lastUsed       DateTime
  user           User       @relation(fields: [userId], references: [id])
}

model DidKey {
  id             String     @id 
  userId         String
  publicKey      String
  createdAt      DateTime   @default(now())
  lastUsed       DateTime
  user           User       @relation(fields: [userId], references: [id])
}


License
This project is licensed under the MIT License - see the LICENSE file for details.