import "./globals.css";import {Nav} from "@/components/nav";
export const metadata={title:"TRAPSIG",description:"IoT cybersecurity experimentation platform"};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body><Nav/><main>{children}</main></body></html>}
