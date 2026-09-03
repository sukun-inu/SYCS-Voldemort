export class ApiError extends Error{constructor(status,payload){super((payload&&(payload.detail||payload.message))||`HTTP ${status}`);this.name="ApiError";this.status=status;this.payload=payload||{};}
get fieldErrors(){return this.payload.errors||{};}}
function csrfToken(){const meta=document.querySelector('meta[name="csrf-token"]');return meta?meta.getAttribute("content")||"":"";}
async function request(method,url,body){const options={method,credentials:"same-origin",cache:"no-store",headers:{Accept:"application/json"},};if(method!=="GET")options.headers["X-CSRFToken"]=csrfToken();if(body!==undefined){options.headers["Content-Type"]="application/json";options.body=JSON.stringify(body);}
const response=await fetch(url,options);if(response.redirected&&new URL(response.url).pathname.startsWith("/admin/login")){window.location.href=response.url;throw new ApiError(401,{detail:"セッションが切れました。ログインし直してください。"});}
let payload=null;if(response.status!==204){try{payload=await response.json();}catch{payload=null;}}
if(!response.ok)throw new ApiError(response.status,payload);return payload||{};}
export const get=(url)=>request("GET",url);export const post=(url,body)=>request("POST",url,body);export const put=(url,body)=>request("PUT",url,body);export const del=(url)=>request("DELETE",url);