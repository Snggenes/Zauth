# Zauth - A Basic Auth Provider For React and Next App Developers

- **Authentication Provider**: Easily wrap your app with Zauth's provider for instant integration.
- **Login and Logout Functions**: Simplify user authentication flows with ready-to-use functions.
- **User Management**: Manage user accounts, roles, and profiles directly within your app.
- **Pre-built Account Management Components**: Include user-friendly components for account updates and settings.
- **Token Management**: Securely handle access and refresh tokens, all abstracted for you.

# Full documentation, client side and node packages will be out very soon. Below you can find some code examples.


Add Zauth to your project using `npm` or `yarn`:

```bash
npm install zauth
```

```jsx
import { ZauthProvider } from "zauth/react";

function App() {
  return <ZauthProvider>{/* Your app's components */}</ZauthProvider>;
}

export default App;
```

```jsx
import { useAuth } from "zauth/react";

function App() {
  const { login, logout } = useAuth();
  return (
    <div>
      <button onClick={login}>Login</button>
      <button onClick={logout}>Logout</button>
    </div>
  );
}

export default App;
```

```jsx
import { useAuth } from "zauth/react";

function App() {
  const { user } = useAuth();
  return (
    <div>
      {user?.id}
      {user?.firstname}
      {user?.lastname}
    </div>
  );
}

export default App;
```
