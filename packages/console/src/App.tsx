import { Navigate, Route, Routes } from "react-router-dom";

import { Shell } from "./components";
import { Account } from "./pages/Account";
import { Activity } from "./pages/Activity";
import { Faucet } from "./pages/Faucet";
import { Overview } from "./pages/Overview";
import { Stake } from "./pages/Stake";
import { Transfer } from "./pages/Transfer";
import { useSession } from "./session";

export function App() {
  const { network } = useSession();
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/account" element={<Account />} />
        <Route path="/transfer" element={<Transfer />} />
        <Route path="/stake" element={<Stake />} />
        <Route path="/activity" element={<Activity />} />
        <Route
          path="/faucet"
          element={network.faucetUrl ? <Faucet /> : <Navigate to="/" replace />}
        />
      </Routes>
    </Shell>
  );
}
