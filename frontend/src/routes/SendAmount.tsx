import { useState } from "react";
import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";
import toast from "react-hot-toast"
import MutinyToaster from "../components/MutinyToaster";
import { useSearchParams } from "react-router-dom";
import ActionButton from "@components/ActionButton";

export default function SendAmount() {
  let navigate = useNavigate();

  const [searchParams] = useSearchParams();
  const destination = searchParams.get("destination")

  const [receiveAmount, setAmount] = useState("")

  function handleContinue() {
    const amount = receiveAmount.replace(/,/g, "")
    if (!amount || amount.match(/\D/)) {
      setAmount('')
      toast("That doesn't look right")
      return
    } else if (parseInt(amount) <= 0) {
      setAmount('')
      toast("You can't send nothing")
      return
    }

    if (destination && amount.match(/^[\d.]+$/)) {
      navigate(`/send/confirm?destination=${destination}&amount=${amount}`)
    }
  }
  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Send" theme="green" />
        <Close />
      </header>
      <ScreenMain>
        <div />
        <div className="flex flex-col gap-4">
          <p className="text-2xl font-light">How much would you like to send?</p>
          <input onChange={e => setAmount(e.target.value)} value={receiveAmount} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" inputMode="numeric" placeholder='sats' />
        </div>
        <ActionButton onClick={handleContinue}>
          Continue
        </ActionButton>
      </ScreenMain>
      <MutinyToaster />
    </>
  );
}
