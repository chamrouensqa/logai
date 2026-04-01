from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.deps import get_current_user
from app.schemas.schemas import IpReputationResponse
from app.services.ip_reputation_service import lookup_ip

router = APIRouter(tags=["IP reputation"], dependencies=[Depends(get_current_user)])


@router.get("/ip-reputation", response_model=IpReputationResponse)
async def get_ip_reputation(ip: str = Query(..., min_length=1, description="IPv4 or IPv6 address")):
    """Return AbuseIPDB and/or VirusTotal enrichment for a public IP (requires API keys on the server)."""
    try:
        return await lookup_ip(ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
