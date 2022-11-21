import { useNavigate } from "react-router-dom"
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"
import { ReactComponent as EjectIcon } from "../images/icons/eject.svg"

function SingleChannel() {
    return (
        <li className="text-off-white border-b border-blue py-2 mb-2 flex flex-col">
            <h3 className="text-lg">
                ACINQ
            </h3>
            <div className="flex items-center gap-4">
                <div className="flex-1 flex flex-col gap-2">
                    <h3 className="text-lg">69_420 sats remaining</h3>
                    <div className="shadow-bar-bg w-full h-6 bg-less-faint rounded">
                        <div className={"shadow-button bg-blue-button h-6 rounded"} style={{ width: `${Math.random() * 100}%` }} />
                    </div>
                </div>
                <button className="h-[3rem] w-[3rem] p-1 flex items-center justify-center flex-0"><EjectIcon /></button>
            </div>
            <small className="text-sm font-light opacity-50 mt-2">abc123nodeid...</small>
        </li>
    )
}

function Channels() {

    const navigate = useNavigate();

    function handleNavOpen() {
        navigate("/openchannel")
    }

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Channels" theme="blue" />
                <Close />
            </header>
            <ScreenMain padSides={false}>
                <button className="mx-8" onClick={handleNavOpen}>Add Channel</button>
                <ul className="flex-1 overflow-y-scroll px-8 pb-[12rem]">
                    <SingleChannel />
                    <SingleChannel />
                    <SingleChannel />
                    <SingleChannel />
                    <SingleChannel />
                </ul>
            </ScreenMain>
        </>
    )
}

export default Channels