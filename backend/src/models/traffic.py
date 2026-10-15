from pydantic import BaseModel


class TrafficEvent(BaseModel):
    timestamp: float

    path: str
    full_url: str
    method: str

    ip: str
    user_agent: str

    referer: str
    host: str
    origin: str

    content_length: int
    content_type: str

    accept: str
    accept_language: str
    accept_encoding: str

    cache_control: str
    connection: str

    query_string: str
    query_param_count: int

    path_depth: int

    protocol: str

    sec_fetch_site: str
    sec_fetch_mode: str
    sec_fetch_dest: str