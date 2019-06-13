defmodule OAuth2.AccessToken do

  import OAuth2.Util

  alias OAuth2.AccessToken

  @standard ["access_token", "refresh_token", "expires_in", "token_type"]

  @type access_token  :: binary
  @type refresh_token :: binary | nil
  @type expires_at    :: integer
  @type token_type    :: binary
  @type other_params  :: %{}
  @type body          :: binary | %{}

  @type t :: %__MODULE__{
              access_token:  access_token,
              refresh_token: refresh_token,
              expires_at:    expires_at,
              token_type:    token_type,
              other_params:  other_params}

  defstruct access_token: "",
            refresh_token: nil,
            expires_at: nil,
            token_type: "Bearer",
            other_params: %{}

  @spec new(binary) :: t
  def new(token) when is_binary(token) do
    new(%{"access_token" => token})
  end

  @spec new(%{binary => binary}) :: t
  def new(response) when is_map(response) do
    {std, other} = Map.split(response, @standard)

    struct(AccessToken, [
      access_token:  std["access_token"],
      refresh_token: std["refresh_token"],
      expires_at:    (std["expires_in"] || other["expires"]) |> expires_at,
      token_type:    std["token_type"] |> normalize_token_type(),
      other_params:  other
    ])
  end

  @spec expires?(AccessToken.t) :: boolean
  def expires?(%AccessToken{expires_at: nil} = _token), do: false
  def expires?(_), do: true

  def expired?(token) do
    expires?(token) && unix_now() > token.expires_at
  end

  def expires_at(nil), do: nil
  def expires_at(val) when is_binary(val) do
    val
    |> Integer.parse
    |> elem(0)
    |> expires_at
  end
  def expires_at(int), do: unix_now() + int

  defp normalize_token_type(nil), do: "Bearer"
  defp normalize_token_type("bearer"), do: "Bearer"
  defp normalize_token_type(string), do: string
end
