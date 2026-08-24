defmodule WeatherAgent.MixProject do
  use Mix.Project

  def project do
    [
      app: :weather_agent,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:langchain, "~> 0.9.0"},
      {:req, "~> 0.5.0"},
      {:jason, "~> 1.4"}
    ]
  end
end
