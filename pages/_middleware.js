import { NextResponse } from "next/server";
import { destroyCookie, setCookie } from "nookies";
import jwt from "@tsndr/cloudflare-worker-jwt"

export async function middleware(req) {
    const path = req.nextUrl.pathname;
    if (path.includes("/api/v1")) return NextResponse.next();
    if (req.cookies.refresh_token && path.includes("/auth") && req.nextUrl.search.includes("login")) return NextResponse.redirect(new URL("/", req.url));
    if (req.cookies.refresh_token || path.includes("/auth") || path.includes("lxd-a")) return NextResponse.next();

    if (jwt.verify(req.cookies.refresh_token, process.env.ENC_KEY) ) {
        let accessToken;
        try {
            accessToken = jwt.sign(jwt.decode(req.cookies.access_token), process.env.ENC_KEY, {
                algorithm: "HS256",
                expiresIn: "15m"
            })
        } catch {
            setCookie(null, "refresh_token", "")
            destroyCookie(null, "refresh_token");
 
            return NextResponse.redirect(new URL("/auth/login", req.url), 307);
        }
        
        setCookie(null, "access_token", accessToken)
        return NextResponse.next();

    } else {
        setCookie(null, "refresh_token", "")
        destroyCookie(null, "refresh_token");
        setCookie(null, "access_token", "");
        destroyCookie(null, "access_token");  
    }
    return NextResponse.redirect(new URL("/auth/login", req.url), 307);
}  
